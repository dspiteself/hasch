(ns hasch.platform
  "Platform specific implementations."
  (:require [hasch.benc :refer [split-size encode-safe]]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [incognito.base :as ib]
            [hasch.benc :refer [magics PHashCoercion -coerce
                                digest coerce-seq xor-hashes encode-safe]])
  (:import java.io.ByteArrayOutputStream
           java.nio.ByteBuffer
           java.nio.charset.StandardCharsets
           java.security.MessageDigest))

(set! *warn-on-reflection* true)

(defn uuid4
  "Generates a UUID version 4 (random)."
  []
  (java.util.UUID/randomUUID))

(defn byte->hex [b]
  (-> b
      (bit-and 0xff)
      (+ 0x100)
      (Integer/toString 16)
      (.substring 1)))

(defn hash->str [bytes]
  (apply str (map byte->hex bytes)))

(defn ^MessageDigest sha512-message-digest []
  (MessageDigest/getInstance "sha-512"))

(defn ^MessageDigest md5-message-digest []
  (MessageDigest/getInstance "md5"))

(defn uuid5-bytes
  "Like `uuid5` but takes the raw (signed) SHA digest byte-array directly.

  `uuid5` accepts the unsigned 0-255 sequence produced by `edn-hash` and rebuilds
  a byte-array from it; that round-trip is a no-op — `(byte-array unsigned-seq)`
  reproduces the original signed digest bytes exactly. Callers that already hold
  the raw digest array (e.g. `hasch.core/uuid`) use this to skip both the lazy
  unsigned seq (~7.8 KB/op) and the byte-array rebuild."
  [^bytes sha-hash]
  (let [bb (ByteBuffer/wrap sha-hash)
        high (.getLong bb)
        low (.getLong bb)]
    (java.util.UUID. (-> high
                         (bit-or 0x0000000000005000)
                         (bit-and 0x7fffffffffff5fff)
                         (bit-clear 63) ;; needed because of BigInt cast of bitmask
                         (bit-clear 62))
                     (-> low
                         (bit-set 63)
                         (bit-clear 62)))))

(defn uuid5
  "Generates a UUID version 5 from a sha-1 hash byte sequence.
Our hash version is coded in first 2 bits."
  [sha-hash]
  (uuid5-bytes (byte-array sha-hash)))

(defn ^bytes encode [^Byte magic ^bytes a]
  ;; Prepend the 1-byte type magic in a single allocation (magic ++ a) instead
  ;; of routing through a ByteArrayOutputStream (which allocated a 1-byte array,
  ;; a growable buffer and a final copy). Byte-identical output.
  (let [len (alength a)
        r (byte-array (inc len))]
    (aset r 0 (byte magic))
    (System/arraycopy a 0 r 1 len)
    r))

(defn- ^bytes str->utf8 [x]
  (.getBytes ^String (str x) StandardCharsets/UTF_8))

;; --- fused map hashing ------------------------------------------------------
;;
;; A map hashes as XOR over `(encode :vector (sha512 (coerce k) ++ (coerce v)))`
;; per entry, truncated to 32 bytes. The naive form materialises, per entry, a
;; MapEntry + seq node (from `(seq m)`/`map`), the 65-byte encoded array, and a
;; lazy-seq cell — all only to be XOR-folded and discarded. Here we fold each
;; entry directly into the 32-byte accumulator: byte 0 XORs the :vector magic,
;; bytes 1..31 XOR digest[0..30]. Entries are visited via `reduce-kv`
;; (IKVReduce: the map's internal reduce — no seq, no MapEntry allocation),
;; falling back to a seq walk for exotic map types. XOR is commutative, so
;; visit order is irrelevant; output is bit-identical to
;; `(xor-hashes (map -coerce (seq m)))`, including `(byte-array 0)` for {}.

;; NOTE on hints in this section: `(defn ^bytes f ...)` return-type tags are a
;; trap — `def` EVALUATES metadata, so the var's :tag becomes the
;; clojure.core/bytes FUNCTION object, and any call site that consults the
;; expression's type (alength/aget on the result) fails to compile. So these
;; helpers carry no return tags; all array interop happens on ^bytes PARAMS.

(defn- map-entry-digest
  "digest of (-coerce k) ++ (-coerce v): the same bytes `coerce-seq` produces
   for the entry viewed as the vector [k v], without allocating the entry."
  [k v md-create-fn write-handlers]
  (let [^MessageDigest md (md-create-fn)]
    (.update md ^bytes (-coerce k md-create-fn write-handlers))
    (.update md ^bytes (-coerce v md-create-fn write-handlers))
    (.digest md)))

(defn- new-acc
  "XOR accumulator sized like xor-hashes' min(count(first-hash), 32), where the
   entry hash is `prefix-len` magic bytes followed by digest `d`:
   SHA-512 map entries -> 32, MD5 map entries -> 17, MD5 set elements -> 16."
  [^bytes d ^long prefix-len]
  (byte-array (min (+ prefix-len (alength d)) 32)))

(defn- xor-map-entry! [^bytes acc ^bytes d]
  ;; entry-hash = [:vector-magic] ++ d, so byte 0 XORs the magic and byte i
  ;; XORs d[i-1] — without materialising the encoded entry array.
  (let [len (alength acc)]
    (aset acc 0 (byte (bit-xor (aget acc 0) 9))) ; 9 = (:vector magics)
    (loop [i 1]
      (when (< i len)
        (aset acc i (byte (bit-xor (aget acc i) (aget d (unchecked-dec i)))))
        (recur (unchecked-inc i))))))

(defn- xor-map-hashes
  "Fused replacement for (xor-hashes (map -coerce (seq m))): each entry's digest
   folds straight into the accumulator — no MapEntry/seq-node/lazy-seq cells and
   no per-entry 65-byte encoded arrays. Entries are visited via `reduce-kv`
   (IKVReduce internal reduce) with a seq-walk fallback for map types without it
   (e.g. struct-map). XOR is commutative so visit order is irrelevant. The
   accumulator is allocated lazily off the first digest ({} yields
   (byte-array 0), as before)."
  [m md-create-fn write-handlers]
  (let [holder (object-array 1)
        fold! (fn [k v]
                (let [d (map-entry-digest k v md-create-fn write-handlers)
                      acc (aget holder 0)
                      acc (if (nil? acc)
                            (let [a (new-acc d 1)] (aset holder 0 a) a)
                            acc)]
                  (xor-map-entry! acc d)))]
    (if (instance? clojure.lang.IKVReduce m)
      (reduce-kv (fn [_ k v] (fold! k v) nil) nil m)
      (loop [s (seq m)]
        (when s
          ;; IMapEntry, not MapEntry: sorted-map seqs yield tree-node entries
          ;; that implement the former but are not instances of the latter.
          (let [^clojure.lang.IMapEntry e (first s)]
            (fold! (.key e) (.val e)))
          (recur (next s)))))
    (let [acc (aget holder 0)]
      (if (nil? acc) (byte-array 0) acc))))

(extend-protocol PHashCoercion
  java.lang.Boolean
  (-coerce [this md-create-fn write-handlers]
    (encode (:boolean magics) (byte-array 1 (if this (byte 41) (byte 40)))))

  ;; don't distinguish characters from string for javascript
  java.lang.Character
  (-coerce [this md-create-fn write-handlers]
    (encode (:string magics) (encode-safe (str->utf8 this) md-create-fn)))

  java.lang.String
  (-coerce [this md-create-fn write-handlers]
    (encode (:string magics) (encode-safe (str->utf8 this) md-create-fn)))

  java.lang.Integer
  (-coerce [this md-create-fn write-handlers]
    (encode (:number magics) (.getBytes (.toString this) StandardCharsets/UTF_8)))

  java.lang.Long
  (-coerce [this md-create-fn write-handlers]
    (encode (:number magics) (.getBytes (.toString this) StandardCharsets/UTF_8)))

  java.math.BigInteger
  (-coerce [this md-create-fn write-handlers]
    (encode (:number magics) (.getBytes (.toString this) StandardCharsets/UTF_8)))

  java.lang.Float
  (-coerce [this md-create-fn write-handlers]
    (encode (:number magics) (.getBytes (.toString this) StandardCharsets/UTF_8)))

  java.lang.Double
  (-coerce [this md-create-fn write-handlers]
    (encode (:number magics) (.getBytes (.toString this) StandardCharsets/UTF_8)))

  java.math.BigDecimal
  (-coerce [this md-create-fn write-handlers]
    (encode (:number magics) (.getBytes (.toString this) StandardCharsets/UTF_8)))

  clojure.lang.BigInt
  (-coerce [this md-create-fn write-handlers]
    (encode (:number magics) (.getBytes (.toString this) StandardCharsets/UTF_8)))

  java.util.UUID
  (-coerce [this md-create-fn write-handlers]
    (encode (:uuid magics) (.getBytes (.toString this) StandardCharsets/UTF_8)))

  java.util.Date
  (-coerce [this md-create-fn write-handlers]
    (encode (:inst magics) (.getBytes (.toString ^java.lang.Long (.getTime this)) StandardCharsets/UTF_8)))

  nil
  (-coerce [this md-create-fn write-handlers]
    (encode (:nil magics) (byte-array 0)))

  clojure.lang.Symbol
  (-coerce [this md-create-fn write-handlers]
    (encode (:symbol magics) (encode-safe (str->utf8 this) md-create-fn)))

  clojure.lang.Keyword
  (-coerce [this md-create-fn write-handlers]
    (encode (:keyword magics) (encode-safe (str->utf8 this) md-create-fn)))

  clojure.lang.ISeq
  (-coerce [this md-create-fn write-handlers]
    (encode (:seq magics) (coerce-seq this md-create-fn write-handlers)))

  clojure.lang.IPersistentVector
  (-coerce [this md-create-fn write-handlers]
    (encode (:vector magics) (coerce-seq this md-create-fn write-handlers)))

  incognito.base.IncognitoTaggedLiteral
  (-coerce [this md-create-fn write-handlers]
    (let [{:keys [tag value]} this]
      (encode (:literal magics) (coerce-seq [tag value] md-create-fn write-handlers))))

  clojure.lang.IRecord
  (-coerce [this md-create-fn write-handlers]
    (let [{:keys [tag value]} (ib/incognito-writer write-handlers this)]
      (encode (:literal magics) (coerce-seq [tag value] md-create-fn write-handlers))))

  clojure.lang.IPersistentMap
  (-coerce [this md-create-fn write-handlers]
    (if (record? this) ;; BUG somehow records can also trigger the map sometimes (?)
      (let [{:keys [tag value]} (ib/incognito-writer write-handlers this)]
        (encode (:literal magics) (coerce-seq [tag value] md-create-fn write-handlers)))
      (encode (:map magics) (xor-map-hashes this md-create-fn write-handlers))))

  clojure.lang.IPersistentSet
  (-coerce [this md-create-fn write-handlers]
    (encode (:set magics) (xor-hashes (map #(digest (-coerce % md-create-fn write-handlers)
                                                    md-create-fn)
                                           (seq this)))))

  ;; not ideal, InputStream might be more flexible
  ;; file is used due to length knowledge
  java.io.File
  (-coerce [f md-create-fn write-handlers]
    (let [^MessageDigest md (md-create-fn)
          len (.length f)]
      (with-open [fis (java.io.FileInputStream. f)]
        (encode (:binary magics)
                ;; support default split-size behaviour transparently
                (if (< len split-size)
                  (let [ba (with-open [out (java.io.ByteArrayOutputStream.)]
                             (clojure.java.io/copy fis out)
                             (.toByteArray out))]
                    (encode-safe ba md-create-fn))
                  (let [ba (byte-array (* 1024 1024))]
                    (loop [size (.read fis ba)]
                      (if (neg? size) (.digest md)
                          (do
                            (.update md ba 0 size)
                            (recur (.read fis ba))))))))))))

(extend (Class/forName "[B")
  PHashCoercion
  {:-coerce (fn [^bytes this md-create-fn write-handlers]
              (encode (:binary magics) (encode-safe this md-create-fn)))})

(comment
  (require '[clojure.java.io :as io])
  (def foo (io/file "/tmp/foo"))
  (.length foo)

  (defn slurp-bytes
    "Slurp the bytes from a slurpable thing"
    [x]
    (with-open [out (java.io.ByteArrayOutputStream.)]
      (clojure.java.io/copy (clojure.java.io/input-stream x) out)
      (.toByteArray out)))

  (clojure.reflect/reflect foo)
  (= (map byte (-coerce (io/file "/tmp/bar") sha512-message-digest))
     (map byte (-coerce (slurp-bytes "/tmp/bar") sha512-message-digest)))

  (map byte (-coerce {:hello :world :foo :bar 1 2} sha512-message-digest))

  (map byte (-coerce #{1 2 3} sha512-message-digest))

  (use 'criterium.core)

  (def million-map (into {} (doall (map vec (partition 2
                                                       (interleave (range 1000000)
                                                                   (range 1000000)))))))

  (bench (-coerce million-map sha512-message-digest)) ;; 3.80 secs

  (def million-seq (doall (map vec (partition 2
                                              (interleave (range 1000000)
                                                          (range 1000000 2000000))))))

  (def million-seq2 (doall (range 1000000)))

  (bench (-coerce million-seq2 sha512-message-digest)) ;; 296 ms

  (bench (-coerce million-seq2 md5-message-digest))

  (take 10 (time (into (sorted-set) (range 1e6)))) ;; 1.7 s

  (bench (coerce-seq sha512-message-digest (seq (into (sorted-set) (range 1e4)))))

  (bench (-coerce (into #{} (range 1e4)) sha512-message-digest))

  (bench (-coerce (seq (into (sorted-set) (range 10))) sha512-message-digest)) ;; 8.6 us

  (bench (-coerce (into #{} (range 10)) sha512-message-digest)) ;; 31.7 us

  (bench (-coerce (seq (into (sorted-set) (range 100))) sha512-message-digest))

  (bench (-coerce (into #{} (range 100)) sha512-message-digest))

  (bench (-coerce (seq (into (sorted-set) (range 1e4))) sha512-message-digest))

  (bench (-coerce (into #{} (range 1e4)) sha512-message-digest))

  (def small-map (into {} (map vec (partition 2 (take 10 (repeatedly rand))))))
  (bench (-coerce (apply concat (seq (into (sorted-map) small-map)))
                  sha512-message-digest)) ;; 12.1 us

  (bench (-coerce small-map sha512-message-digest)) ;; 20.7 us

  (def medium-map (into {} (map vec (partition 2 (take 2e6 (repeatedly rand))))))
  (bench (-coerce (apply concat (seq (into (sorted-map) medium-map)))
                  sha512-message-digest))

  (bench (-coerce medium-map sha512-message-digest))

  (def million-set (doall (into #{} (range 1000000))))

  (bench (-coerce million-set sha512-message-digest)) ;; 2.69 secs

  (def million-seq3 (doall (repeat 1000000 "hello world")))

  (bench (-coerce million-seq3 sha512-message-digest)) ;; 916 msecs

  (def million-seq4 (doall (repeat 1000000 :foo/bar)))

  (bench (-coerce million-seq4 sha512-message-digest)) ;; 752 msecs

  (def datom-vector (doall (vec (repeat 10000 {:db/id 18239
                                               :person/name "Frederic"
                                               :person/familyname "Johanson"
                                               :person/street "Fifty-First Street 53"
                                               :person/postal 38237
                                               :person/phone "02343248474"
                                               :person/weight 38.23}))))
  (let [val (doall (vec (repeat 10000 {:db/id 18239
                                       :person/name "Frederic"
                                       :person/familyname "Johanson"
                                       :person/street "Fifty-First Street 53"
                                       :person/postal 38237
                                       :person/phone "02343248474"
                                       :person/weight 38.23})))]
    (bench (-coerce val sha512-message-digest)))

  (time (-coerce datom-vector sha512-message-digest))
  (bench (-coerce datom-vector sha512-message-digest)) ;; xor: 316 ms, sort: 207 ms

  ;; if not single or few byte values, but at least 8 byte size factor per item ~12x
  ;; factor for single byte ~100x
  (def bs (apply concat (repeat 100000 (.getBytes "Hello World!"))))
  (def barr #_(byte-array bs) (byte-array (* 1024 1024 300) (byte 42)))
  (def barrs (doall (take (* 1024 1024 10) (repeat (byte-array 1 (byte 42))))
                    #_(map byte-array (partition 1 barr))))

  (bench (-coerce barr sha512-message-digest)) ;; 1.99 secs

  (def arr (into-array Byte/TYPE (take (* 1024) (repeatedly #(- (rand-int 256) 128)))))

;; hasch 0.2.3
  (use 'criterium.core)

  (def million-map (into {} (doall (map vec (partition 2
                                                       (interleave (range 1000000)
                                                                   (range 1000000 2000000)))))))

  (bench (uuid million-map)) ;; 27 secs

  (def million-seq3 (doall (repeat 1000000 "hello world")))

  (bench (uuid million-seq3)) ;; 16 secs

  (def datom-vector (doall (vec (repeat 10000 {:db/id 18239
                                               :person/name "Frederic"
                                               :person/familyname "Johanson"
                                               :person/street "Fifty-First Street 53"
                                               :person/postal 38237
                                               :person/telefon "02343248474"
                                               :person/weeight 0.3823}))))

  (bench (uuid datom-vector)) ;; 2.6 secs
  )
