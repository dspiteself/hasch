(ns bench
  "Allocation + throughput micro-benchmark for hasch's hashing hot path.

  Measures ns/op and bytes/op (via com.sun.management.ThreadMXBean) for the
  Coding / CodeableConcept / Observation shapes the Datomic transactor hashes.

  Run against the current source:
      clojure -M:bench

  Compare against a baseline checkout by pointing the classpath at another src:
      clojure -Sdeps '{:deps {org.clojure/clojure {:mvn/version \"1.11.1\"}
                              io.replikativ/incognito {:mvn/version \"0.3.66\"}}
                       :paths [\"/path/to/baseline/src\" \"dev\"]}' -M -m bench

  See docs/allocation-analysis.md for recorded before/after numbers."
  (:require [hasch.core :as h])
  (:import [java.lang.management ManagementFactory]
           [com.sun.management ThreadMXBean]))

(def ^ThreadMXBean tmx (ManagementFactory/getThreadMXBean))
(defn alloc-bytes [] (.getThreadAllocatedBytes tmx (.getId (Thread/currentThread))))

(defn bench-alloc [label f iters warmup]
  (dotimes [_ warmup] (f))
  (System/gc) (Thread/sleep 50)
  (let [t0 (System/nanoTime) a0 (alloc-bytes)]
    (dotimes [_ iters] (f))
    (let [a1 (alloc-bytes) t1 (System/nanoTime)]
      {:label label
       :ns-per-op (Math/round (double (/ (- t1 t0) iters)))
       :bytes-per-op (Math/round (double (/ (- a1 a0) iters)))})))

(def coding {:system "http://loinc.org" :code "1234-5" :display "Body Weight"})
(def cc {:coding [{:system "http://loinc.org" :code "1234-5" :display "Body Weight"}
                  {:system "http://snomed.info/sct" :code "27113001" :display "Body weight"}]
         :text "Body Weight"})
(def observation
  {:resourceType "Observation" :status "final"
   :code {:coding [{:system "http://loinc.org" :code "29463-7" :display "Body Weight"}] :text "Weight"}
   :valueQuantity {:value 72.5 :unit "kg" :system "http://unitsofmeasure.org" :code "kg"}})
;; a 20-coding CodeableConcept-heavy vector, closer to a decant batch element
(def cc-batch (vec (repeat 20 cc)))
;; wide map — stresses the per-entry path
(def bigmap (into {} (map (fn [i] [(keyword (str "k" i)) (str "value-string-" i)]) (range 200))))
;; datomic-style entity: cardinality-many attributes pull SET values
(def entity {:person/name "Frederic"
             :person/aliases #{"Fred" "Freddy" "F-Dog" "Frederic the Great"}
             :person/tags #{:vip :beta-tester :early-adopter}
             :person/emails #{"fred@example.com" "freddy@example.org"}})
(def bigset (into #{} (map #(str "member-" %) (range 200))))

(defn -main [& _]
  (let [results
        [(bench-alloc "edn-hash coding (realized)" #(doall (h/edn-hash coding)) 400000 40000)
         (bench-alloc "uuid coding"                #(h/uuid coding)             400000 40000)
         (bench-alloc "edn-hash cc (realized)"     #(doall (h/edn-hash cc))     300000 30000)
         (bench-alloc "uuid cc"                    #(h/uuid cc)                 300000 30000)
         (bench-alloc "uuid observation"           #(h/uuid observation)        300000 30000)
         (bench-alloc "uuid cc-batch(20)"          #(h/uuid cc-batch)            50000  5000)
         (bench-alloc "b64-hash coding"            #(h/b64-hash coding)         300000 30000)
         (bench-alloc "b64-hash cc"                #(h/b64-hash cc)             300000 30000)
         (bench-alloc "uuid bigmap(200)"           #(h/uuid bigmap)              10000  1000)
         (bench-alloc "uuid entity(sets)"          #(h/uuid entity)             200000 20000)
         (bench-alloc "uuid bigset(200)"           #(h/uuid bigset)              10000  1000)]]
    (println "=== hasch benchmark ===")
    (doseq [r results]
      (println (format "%-28s %8d ns/op  %8d B/op"
                       (:label r) (:ns-per-op r) (:bytes-per-op r))))
    (shutdown-agents)))
