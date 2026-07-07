(ns hasch.core
  "Hashing functions for EDN."
  #?(:cljs (:refer-clojure :exclude [uuid]))
  (:require [hasch.benc :refer [PHashCoercion -coerce digest] :as benc]
            [hasch.base64 :as b64]
            [hasch.platform :as platform]))

(def uuid4 platform/uuid4)
(def uuid5 platform/uuid5)
(def hash->str platform/hash->str)
(def hash-ref? benc/hash-ref?)

(defn edn-hash-bytes
  "Hash an edn value like `edn-hash`, but return the raw digest platform-natively:
  a signed `byte[]` on the JVM, an unsigned array on ClojureScript — instead of
  `edn-hash`'s lazy seq of unsigned numbers.

  The digest *bytes* are exactly `edn-hash`'s (on the JVM
  `(byte-array (edn-hash v))` == `(edn-hash-bytes v)` bit for bit), so hashes
  remain interchangeable; only the container differs. Prefer this in hot paths:
  it avoids materialising the 64-element unsigned lazy seq (~7.8 KB/op) that
  dominates `edn-hash`'s allocation profile. NOTE: on the JVM byte arrays use
  identity equality — compare with `java.util.Arrays/equals` or via `uuid`."
  ([val] (edn-hash-bytes val {}))
  ([val write-handlers] (edn-hash-bytes val platform/sha512-message-digest write-handlers))
  ([val md-create-fn write-handlers]
   (digest (-coerce val md-create-fn (or write-handlers {})) md-create-fn)))

(defn edn-hash
  "Hash an edn value with SHA-512 by default or a compatible hash function of choice.

  Please use the write-handlers only in legacy cases and rather extend the PHashCoercion
  protocol to your own types."
  ([val] (edn-hash val {}))
  ([val write-handlers] (edn-hash val hasch.platform/sha512-message-digest write-handlers))
  ([val md-create-fn write-handlers]
   (map #(if (neg? %) (+ % 256) %) ;; make unsigned
        (edn-hash-bytes val md-create-fn write-handlers))))

(defn uuid
  "Creates random UUID-4 without argument or UUID-5 for the argument value.

  Optionally an incognito-style write-handlers map can be supplied,
  which describes record serialization in terms of Clojure data
  structures."
  ([] (uuid4))
  ([val & {:keys [write-handlers]}]
   (platform/uuid5-bytes (edn-hash-bytes val write-handlers))))

(defn squuid
  "Calculates a sequential UUID as described in
  https://github.com/clojure-cookbook/clojure-cookbook/blob/master/01_primitive-data/1-24_uuids.asciidoc"
  ([] (squuid (uuid4)))
  ([uuid]
   #?(:clj
      (let [time (System/currentTimeMillis)
            secs (quot time 1000)
            lsb (.getLeastSignificantBits ^java.util.UUID uuid)
            msb (.getMostSignificantBits ^java.util.UUID uuid)
            timed-msb (bit-or (bit-shift-left secs 32)
                              (bit-and 0x00000000ffffffff msb))]
        (java.util.UUID. timed-msb lsb))
      :cljs
      (let [time (.getTime (js/Date.))
            secs (quot time 1000)
            prefix (.toString secs 16)]
        (cljs.core/uuid (str prefix (subs (str uuid) 8)))))))

(defn b64-hash
  "Provides a base64 encoded string of the edn-hash of a value val. This contains
  all bits of the hash compared to 128 bits for the UUID-5. Both should be safe,
  but b64-hash is safer towards collisions."
  [val]
  ;; The raw digest is what `(byte-array (edn-hash val))` / `(clj->js (edn-hash val))`
  ;; reconstructed anyway; encoding it directly skips the unsigned lazy seq and
  ;; the array rebuild. Same base64 string.
  (b64/encode (edn-hash-bytes val)))

(defn hash-ref
  "Create a HashRef from a value. Stores the -coerce output so that when
   the HashRef appears inside a larger structure, it produces the same hash
   as the original value — transparent merkle-style structural hashing.

   (edn-hash (hash-ref x)) == (edn-hash x)
   (uuid {:a (hash-ref x)}) == (uuid {:a x})"
  ([val] (hash-ref val platform/sha512-message-digest {}))
  ([val write-handlers] (hash-ref val platform/sha512-message-digest write-handlers))
  ([val md-create-fn write-handlers]
   (benc/->HashRef (-coerce val md-create-fn (or write-handlers {})))))

(defn ref->uuid
  "The UUID-5 the ORIGINAL value hashes to — i.e. `(uuid val)` — recovered from its
   `HashRef` ALONE, without the value. A `HashRef` stores the value's `-coerce` output
   (the pre-digest bytes); re-digesting them reproduces `edn-hash` → `uuid5`.

     (= (ref->uuid (hash-ref v)) (uuid v))

   So a content-addressed store keyed by `(uuid val)` can be traversed / garbage-collected
   by following `HashRef`s embedded in other stored values — no original value required."
  ([hash-ref] (ref->uuid hash-ref platform/sha512-message-digest))
  ([hash-ref md-create-fn]
   ;; Same raw-digest fast path as `uuid`: `uuid5` would rebuild a byte-array from
   ;; the unsigned lazy seq, and `(byte-array (map make-unsigned raw)) == raw`, so
   ;; feed the raw digest straight to `uuid5-bytes`. Identical UUID, no unsigned
   ;; seq (~7.8 KB/op) and no array rebuild.
   (platform/uuid5-bytes (digest (:hash-bytes hash-ref) md-create-fn))))
