(ns hasch.benc
  "Binary encoding of EDN values."
  #?@(:clj [(:import java.security.MessageDigest
                     java.io.ByteArrayOutputStream
                     java.util.ArrayDeque
                     java.util.IdentityHashMap
                     java.util.function.Supplier)]))

#?(:clj (set! *warn-on-reflection* true))

(defprotocol PHashCoercion
  (-coerce [this md-create-fn write-handlers]))

;; changes break hashes!
(def magics {:nil (byte 0)
             :boolean (byte 1)
             :number (byte 2)
             :string (byte 3)
             :symbol (byte 4)
             :keyword (byte 5)
             :inst (byte 6)
             :uuid (byte 7)
             :seq (byte 8)
             :vector (byte 9)
             :map (byte 10)
             :set (byte 11)
             :literal (byte 12)
             :binary (byte 13)})

(defrecord HashRef [hash-bytes]
  PHashCoercion
  (-coerce [_this _md-create-fn _write-handlers]
    hash-bytes))

(defn hash-ref?
  "Is `x` a HashRef (a content-address pointer)? Cross-platform."
  [x]
  (instance? HashRef x))

(def split-size 1024)

(def max-entropy-byte-count 32)

#?(:cljs (defn- byte-array [len] (into-array (repeat len 0))))

;; --- MessageDigest reuse (JVM) ---------------------------------------------
;;
;; The hot path allocates one `MessageDigest` per collection / seq / map-entry
;; (4 per Coding, 10 per CodeableConcept). Each `MessageDigest/getInstance`
;; both allocates a ~384 byte stateful object AND does a synchronized provider
;; lookup. `MessageDigest.digest()` leaves the instance reset (ready to reuse),
;; so we keep a per-thread free-list keyed by `md-create-fn` identity and hand
;; instances back after each digest. Nested digests are live simultaneously
;; (e.g. a vector's seq-md while its elements hash), but each borrows a distinct
;; instance and only returns it AFTER `.digest`, so no instance is ever aliased
;; across two live computations. On exception an instance is simply dropped
;; (never returned) — the pool shrinks, hashes stay correct. Keyed by
;; `md-create-fn` so the default SHA-512 and a caller's MD5 never mix.
;;
;; ClojureScript has no threads; there `borrow-md` just calls the factory and
;; `release-md` is a no-op, i.e. behaviour is identical to the original code.
#?(:clj
   (def ^:private ^ThreadLocal md-pool
     (ThreadLocal/withInitial
      (reify Supplier (get [_] (IdentityHashMap.))))))

#?(:clj
   (defn ^MessageDigest borrow-md
     "Return a reset MessageDigest produced by `md-create-fn`, reusing a
      previously released one for this thread+factory when available."
     [md-create-fn]
     (let [^IdentityHashMap m (.get md-pool)
           ^ArrayDeque dq (or (.get m md-create-fn)
                              (let [d (ArrayDeque.)] (.put m md-create-fn d) d))
           md (.pollFirst dq)]
       (if (nil? md) (md-create-fn) md))))

#?(:clj
   (defn release-md
     "Return a just-digested (hence reset) MessageDigest to the free-list."
     [md-create-fn ^MessageDigest md]
     (let [^IdentityHashMap m (.get md-pool)
           ^ArrayDeque dq (.get m md-create-fn)]
       (.addFirst dq md)
       nil)))

#?(:cljs
   (do
     (defn borrow-md [md-create-fn] (md-create-fn))
     (defn release-md [_md-create-fn _md] nil)))

(defn ^bytes digest
  [bytes-or-seq-of-bytes md-create-fn]
  (let [^MessageDigest md (borrow-md md-create-fn)]
    (if (seq? bytes-or-seq-of-bytes)
      (doseq [^bytes bs bytes-or-seq-of-bytes]
        (.update md bs))
      (.update md  ^bytes bytes-or-seq-of-bytes))
    (let [out (.digest md)]
      (release-md md-create-fn md)
      out)))

(defn ^bytes coerce-seq [seq md-create-fn write-handlers]
  (let [^MessageDigest seq-md (borrow-md md-create-fn)]
    (loop [s seq]
      (let [[f & r] s]
        (.update seq-md  ^bytes (-coerce f md-create-fn write-handlers))
        (when-not (empty? r)
          (recur (rest s)))))
    (let [out (.digest seq-md)]
      (release-md md-create-fn seq-md)
      out)))

(defn ^bytes xor-hashes
  "Commutatively coerces elements of collection, seq entries must already be crypto hashes
  to avoid collisions in XOR. Takes at maximum 32 bytes into account."
  [seq]
  (let [len (min (count  ^bytes (first seq)) max-entropy-byte-count)]
    (reduce (fn [^bytes acc  ^bytes elem]
              (loop [i 0]
                (when (< i len)
                  (aset acc i (byte (bit-xor (aget acc i) (aget elem i))))
                  (recur (inc i))))
              acc)
            (byte-array len)
            seq)))

(defn ^bytes encode-safe [^bytes a md-create-fn]
  (if (< (count a) split-size)
    #?(:clj
       ;; Build the `a ++ escape-markers` array in a single allocation:
       ;; the low half is a copy of `a`, the (zero-initialised) high half gets a
       ;; 1 wherever a[i] is a control-ish byte (0 < a[i] < 30). This is
       ;; byte-identical to the previous ByteArrayOutputStream(a, ea) output but
       ;; avoids the extra `ea` array, the stream's growable buffer and its copy.
       (let [len (long (alength a))
             r (byte-array (* 2 len))]
         (System/arraycopy a 0 r 0 len)
         (loop [i 0]
           (when-not (= i len)
             (let [e (aget a i)]
               (when (and (> e (byte 0))
                          (< e (byte 30)))
                 (aset r (+ len i) (byte 1))))
             (recur (inc i))))
         r)
       :cljs
       (let [len (long (alength a))
             ea (byte-array len)]
         (loop [i 0]
           (when-not (= i len)
             (let [e (aget a i)]
               (when (and (> e (byte 0))
                          (< e (byte 30)))
                 (aset ea i (byte 1))))
             (recur (inc i))))
         (.concat a ea)))
    (digest a md-create-fn)))
