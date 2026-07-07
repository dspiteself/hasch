(ns hasch.identity-test
  "Hash-identity regression pins for the allocation-reduction work on
   `perf/reduce-allocations`.

   hasch is used as a *content-addressing* library: `(uuid v)` / `(edn-hash v)`
   are stable keys for stored data (e.g. Coding / CodeableConcept entities hashed
   inside the Datomic transactor's `:db/fns`). Any change to the produced bytes
   would silently break every previously-stored address.

   The expected values below were captured from hasch 0.3.94 (tag `0.3.94`,
   commit d9efe49) BEFORE any optimization. Every allocation-reduction change on
   this branch must keep these bit-identical: SHA-512 makes a hash collision
   astronomically unlikely, so identical `edn-hash`/`uuid` outputs across this
   corpus is a strong proof that the pre-digest byte encoding is unchanged."
  (:require [hasch.core :refer [edn-hash uuid]]
            [hasch.platform :refer [md5-message-digest]]
            [incognito.base :as ib]
            [clojure.test :refer [deftest testing is]]))

;; Representative corpus: primitives, strings, keywords, symbols, numbers, nil,
;; uuids, insts, empty/typed collections, sets, maps, plus the FHIR shapes that
;; motivate this work (Coding, CodeableConcept, nested Observation) and an
;; incognito tagged-literal (record serialization path).
(def corpus
  [nil true false
   "hello" "" "小鳩ちゃんかわいいなぁ" "http://loinc.org"
   \f \ä
   :core/test :code :a
   'core/+ 'sym
   (int 1234567890) (long 42) (double 123.1) (float 1.5) 0 -1 (biginteger "999999999999999999999999")
   #uuid "242525f1-8ed7-5979-9232-6992dd1e11e4"
   (java.util.Date. 1000000000000)
   [] [1 2 3] [:a "b" 3]
   '() '(1 2 3)
   #{} #{1 2 3} #{:a :b :c}
   {} {:a 1}
   {:system "http://loinc.org" :code "1234-5" :display "Body Weight"}
   {:coding [{:system "http://loinc.org" :code "1234-5" :display "Body Weight"}
             {:system "http://snomed.info/sct" :code "27113001" :display "Body weight"}]
    :text "Body Weight"}
   {:resourceType "Observation"
    :status "final"
    :code {:coding [{:system "http://loinc.org" :code "29463-7" :display "Body Weight"}]
           :text "Weight"}
    :valueQuantity {:value 72.5 :unit "kg" :system "http://unitsofmeasure.org" :code "kg"}}
   (ib/map->IncognitoTaggedLiteral {:tag 'foo/Bar :value {:name "x"}})])

;; Pinned expected values (edn-hash as unsigned-byte vector, uuid as string),
;; captured from unmodified hasch 0.3.94. Order matches `corpus`.
(def expected
  [{:edn [184 36 77 2 137 129 214 147 175 123 69 106 248 239 164 202 214 61 40 46 25 255 20 148 44 36 110 80 217 53 29 34 112 74 128 42 113 195 88 11 99 112 222 76 235 41 60 50 74 132 35 52 37 87 212 229 195 132 56 240 227 105 16 238] :uuid "38244d02-8981-5693-af7b-456af8efa4ca"}
   {:edn [221 223 252 44 103 48 51 199 71 184 156 187 201 140 35 99 235 153 185 70 157 229 122 4 111 90 12 150 43 67 185 166 210 79 54 62 117 173 76 252 187 67 163 85 202 124 63 252 109 44 47 70 74 129 52 241 35 15 116 253 241 141 50 131] :uuid "1ddffc2c-6730-53c7-87b8-9cbbc98c2363"}
   {:edn [54 0 110 63 158 137 176 89 220 235 107 213 84 159 27 25 148 206 193 96 192 73 41 255 220 181 215 106 208 220 173 69 213 190 181 70 141 193 1 225 188 142 127 176 102 61 13 54 151 161 195 158 152 190 212 168 91 43 153 108 122 123 90 32] :uuid "36006e3f-9e89-5059-9ceb-6bd5549f1b19"}
   {:edn [178 114 9 243 3 150 0 132 236 216 60 87 108 34 2 35 85 37 203 202 97 176 9 55 25 191 143 251 251 47 49 139 99 191 77 63 167 158 61 183 233 59 43 57 16 252 121 198 65 201 112 167 96 61 134 122 177 149 45 87 233 23 173 192] :uuid "327209f3-0396-5084-acd8-3c576c220223"}
   {:edn [228 91 245 129 125 223 148 170 47 122 64 112 113 240 238 220 107 235 152 247 104 180 205 51 209 23 109 68 209 86 58 69 165 215 33 34 144 235 118 112 198 120 107 19 89 26 237 172 134 71 137 147 137 94 139 36 230 18 1 74 186 166 186 4] :uuid "245bf581-7ddf-54aa-af7a-407071f0eedc"}
   {:edn [2 191 84 39 34 44 227 102 135 109 17 136 159 80 253 7 40 0 170 134 198 204 137 10 194 21 113 203 2 87 125 80 172 165 111 110 222 7 123 138 148 124 207 180 240 207 91 6 248 28 53 168 143 30 106 103 101 82 133 215 69 35 93 47] :uuid "02bf5427-222c-5366-876d-11889f50fd07"}
   {:edn [145 161 41 216 11 205 181 188 224 217 12 89 83 87 134 141 177 51 200 105 140 156 162 41 235 59 21 49 238 161 17 192 195 130 137 59 1 62 99 249 147 107 233 130 134 95 26 162 46 158 17 87 208 160 44 106 90 180 73 123 38 109 227 155] :uuid "11a129d8-0bcd-55bc-a0d9-0c595357868d"}
   {:edn [211 133 203 224 194 174 136 44 216 77 98 85 54 188 116 101 139 174 40 108 48 180 235 231 214 189 34 246 32 30 56 45 179 218 36 206 61 191 79 160 212 162 212 226 235 17 27 228 218 74 17 229 9 147 187 232 35 244 179 233 66 165 152 253] :uuid "1385cbe0-c2ae-582c-984d-625536bc7465"}
   {:edn [51 232 113 238 243 104 216 10 143 88 143 111 122 220 35 138 251 22 8 130 238 73 253 62 143 207 208 45 116 21 120 18 253 34 160 30 144 46 182 7 160 254 197 120 199 220 140 209 3 66 25 214 131 145 17 222 28 157 22 103 226 254 178 186] :uuid "33e871ee-f368-580a-8f58-8f6f7adc238a"}
   {:edn [62 51 214 78 41 84 37 205 69 197 105 26 235 55 30 87 46 117 187 194 101 184 139 244 111 232 98 175 16 174 182 211 11 171 154 64 90 18 229 93 188 246 33 234 102 145 68 30 92 0 81 208 210 10 124 137 203 18 249 138 226 253 60 62] :uuid "3e33d64e-2954-55cd-85c5-691aeb371e57"}
   {:edn [215 120 205 100 5 73 84 192 233 146 149 52 1 3 231 223 172 16 245 66 130 49 251 117 43 18 179 169 172 2 234 15 148 34 110 171 0 35 73 84 60 111 243 78 14 142 180 53 13 145 140 187 135 58 48 191 80 87 94 0 75 117 59 167] :uuid "1778cd64-0549-54c0-a992-95340103e7df"}
   {:edn [161 232 68 7 71 172 226 194 85 103 182 17 130 5 193 183 232 1 2 13 122 12 55 1 160 120 56 29 191 221 193 141 130 134 97 180 167 127 147 106 84 116 4 52 62 40 182 222 119 121 232 123 241 213 153 189 92 196 166 147 50 144 73 68] :uuid "21e84407-47ac-52c2-9567-b6118205c1b7"}
   {:edn [164 63 64 77 190 144 72 80 34 36 254 237 101 99 57 114 54 44 195 22 255 11 242 114 99 87 99 135 103 73 164 183 20 192 184 54 183 244 192 151 88 96 55 204 73 156 73 92 154 8 248 205 119 157 34 112 202 51 52 169 162 61 91 235] :uuid "243f404d-be90-5850-a224-feed65633972"}
   {:edn [30 3 254 193 120 119 224 48 154 108 64 196 239 45 129 205 230 50 216 64 235 21 125 78 228 69 250 39 253 123 143 30 227 152 12 183 56 76 52 125 111 1 94 160 76 244 253 100 115 124 246 164 189 21 123 172 150 15 192 217 28 148 99 54] :uuid "1e03fec1-7877-5030-9a6c-40c4ef2d81cd"}
   {:edn [65 199 158 164 193 95 213 144 233 29 41 86 123 106 110 215 117 225 149 249 204 124 220 217 226 120 131 178 61 133 39 228 182 233 235 249 10 249 141 122 101 25 46 134 18 222 175 224 134 61 167 114 15 109 2 146 38 65 1 55 128 137 144 55] :uuid "01c79ea4-c15f-5590-a91d-29567b6a6ed7"}
   {:edn [15 194 10 154 193 83 121 45 136 138 112 127 243 6 251 182 58 173 113 182 224 92 33 30 218 231 12 85 21 159 119 220 100 3 127 166 108 159 137 236 83 16 109 162 150 132 145 22 45 205 29 82 66 57 79 169 11 46 106 122 133 46 240 201] :uuid "0fc20a9a-c153-592d-888a-707ff306fbb6"}
   {:edn [155 181 33 252 126 113 188 20 210 155 50 24 125 212 205 160 135 108 90 43 154 65 61 229 226 83 11 110 64 61 124 45 43 186 152 127 64 171 171 154 28 149 180 136 229 69 195 145 126 99 56 14 48 194 180 126 212 83 123 206 36 189 189 167] :uuid "1bb521fc-7e71-5c14-929b-32187dd4cda0"}
   {:edn [91 161 185 99 247 157 74 254 209 129 206 105 74 163 135 45 54 116 195 18 161 238 197 28 243 235 97 126 231 0 254 104 157 198 8 125 148 30 2 3 138 207 112 23 205 54 62 91 190 100 193 241 86 205 85 210 14 174 21 6 14 34 151 15] :uuid "1ba1b963-f79d-5afe-9181-ce694aa3872d"}
   {:edn [11 14 147 22 122 43 3 54 156 219 123 27 245 244 103 88 146 154 252 218 91 187 99 202 72 151 2 134 80 224 36 68 15 112 52 24 230 61 106 89 220 199 245 117 56 223 8 219 26 164 132 97 159 145 193 231 190 71 132 239 189 144 123 21] :uuid "0b0e9316-7a2b-5336-9cdb-7b1bf5f46758"}
   {:edn [215 235 150 81 229 251 218 208 1 156 199 111 238 247 158 174 107 78 86 104 140 34 61 224 146 184 115 252 16 0 212 86 141 148 81 43 31 195 195 231 234 243 240 247 241 149 3 15 183 8 53 27 141 134 78 82 157 158 12 101 120 138 101 230] :uuid "17eb9651-e5fb-5ad0-819c-c76feef79eae"}
   {:edn [106 201 42 2 135 93 191 165 204 75 192 225 17 109 246 1 95 153 196 186 29 225 252 22 19 170 227 63 111 41 59 140 231 179 13 224 50 10 119 138 121 168 67 134 119 247 131 152 87 51 55 101 101 79 241 247 81 167 95 217 234 15 170 163] :uuid "2ac92a02-875d-5fa5-8c4b-c0e1116df601"}
   {:edn [42 243 183 237 233 94 246 1 110 56 231 49 64 217 181 17 108 11 120 199 223 53 149 47 49 8 109 94 127 93 250 51 167 211 25 31 3 171 149 67 23 245 38 248 40 31 199 211 162 242 120 99 187 6 29 237 53 174 22 192 27 159 227 164] :uuid "2af3b7ed-e95e-5601-ae38-e73140d9b511"}
   {:edn [177 226 212 235 221 67 176 34 184 69 101 45 117 193 95 187 54 50 210 149 10 193 10 67 220 174 25 99 176 115 250 216 29 49 148 167 52 86 203 90 30 170 62 149 115 102 109 120 128 62 2 213 188 41 203 91 202 106 142 100 119 160 26 3] :uuid "31e2d4eb-dd43-5022-b845-652d75c15fbb"}
   {:edn [145 121 53 166 138 189 39 181 23 79 78 255 147 152 154 218 69 110 41 139 240 222 207 27 169 64 54 29 89 27 114 93 6 60 62 253 86 157 101 238 234 164 27 49 182 102 108 212 228 215 24 21 67 230 3 196 73 240 27 207 1 146 22 53] :uuid "117935a6-8abd-57b5-974f-4eff93989ada"}
   {:edn [192 189 45 203 92 21 181 94 161 200 97 102 167 143 200 8 4 107 168 54 236 80 174 120 41 31 135 233 140 224 152 191 136 255 163 140 185 121 162 232 121 10 190 135 192 4 1 2 237 42 237 145 50 229 81 110 227 103 192 16 12 249 255 206] :uuid "00bd2dcb-5c15-555e-a1c8-6166a78fc808"}
   {:edn [108 86 81 251 197 152 72 211 66 194 150 92 1 5 155 90 132 86 212 226 251 45 160 160 210 31 210 176 42 233 53 149 41 167 79 5 162 146 64 138 85 227 130 0 106 83 13 149 61 239 241 31 140 145 222 52 41 245 252 25 182 195 7 37] :uuid "2c5651fb-c598-58d3-82c2-965c01059b5a"}
   {:edn [175 174 167 119 32 60 102 47 169 227 48 10 209 163 110 135 49 22 206 236 180 124 253 46 175 173 35 22 19 251 37 87 200 46 39 133 120 218 132 240 46 181 20 203 205 236 84 231 241 106 145 243 149 14 179 188 25 138 254 56 7 212 106 248] :uuid "2faea777-203c-562f-a9e3-300ad1a36e87"}
   {:edn [244 105 186 110 183 117 195 78 70 57 251 132 133 114 134 175 228 94 242 41 194 191 186 237 163 178 255 193 141 120 5 137 223 130 170 47 231 133 78 131 128 194 115 140 186 169 124 71 205 210 228 236 82 97 166 158 190 98 106 80 237 149 96 102] :uuid "3469ba6e-b775-534e-8639-fb84857286af"}
   {:edn [82 124 255 43 111 223 188 15 84 254 9 43 23 214 216 199 226 37 0 36 38 53 250 86 152 30 133 166 77 166 206 138 18 163 166 108 246 159 212 143 88 139 203 169 186 209 65 184 227 81 160 205 212 146 90 229 114 137 147 62 236 31 193 83] :uuid "127cff2b-6fdf-5c0f-94fe-092b17d6d8c7"}
   {:edn [1 247 146 117 94 174 36 110 215 217 199 78 121 8 20 40 105 243 17 59 235 239 51 191 133 81 219 151 3 160 91 201 106 78 4 219 20 114 17 220 221 231 161 71 111 50 60 183 3 55 177 250 155 175 146 46 81 3 133 136 174 224 204 163] :uuid "01f79275-5eae-546e-97d9-c74e79081428"}
   {:edn [74 252 149 27 97 33 209 116 43 153 73 193 173 172 168 23 29 172 80 234 84 54 184 34 176 151 193 130 193 248 18 76 122 135 245 222 79 246 5 201 137 200 51 183 29 252 83 243 188 219 177 41 221 171 214 164 224 48 187 46 168 161 106 6] :uuid "0afc951b-6121-5174-ab99-49c1adaca817"}
   {:edn [190 104 136 56 202 134 134 229 201 6 137 191 42 181 133 206 241 19 124 153 155 72 199 11 146 246 122 92 52 220 21 105 123 93 17 201 130 237 109 113 190 30 30 127 123 78 7 51 136 74 169 124 63 122 51 154 142 208 53 119 207 116 190 9] :uuid "3e688838-ca86-56e5-8906-89bf2ab585ce"}
   {:edn [1 224 219 252 114 201 149 37 242 58 146 49 154 0 182 154 103 76 201 114 171 255 23 84 188 69 123 45 68 254 215 10 165 195 97 200 44 187 24 172 186 161 210 238 88 245 132 231 65 231 12 17 241 3 21 164 47 150 72 239 233 165 166 113] :uuid "01e0dbfc-72c9-5525-b23a-92319a00b69a"}
   {:edn [1 92 92 247 85 140 132 144 128 133 66 79 243 49 58 28 44 93 175 197 85 133 193 83 87 196 69 219 47 172 206 203 47 229 179 100 142 67 165 30 66 178 210 225 190 187 239 146 176 49 253 6 122 233 201 133 127 247 193 26 189 48 205 197] :uuid "015c5cf7-558c-5490-8085-424ff3313a1c"}
   {:edn [3 2 246 97 210 32 94 217 13 101 70 139 198 155 43 103 96 84 39 17 133 149 107 79 39 108 125 110 53 185 215 238 19 7 21 255 162 136 118 194 251 121 232 203 224 205 85 166 221 255 149 62 25 67 251 90 68 109 187 59 112 8 255 101] :uuid "0302f661-d220-5ed9-8d65-468bc69b2b67"}
   {:edn [57 244 54 139 90 128 67 75 150 77 223 251 181 241 2 42 7 200 84 198 53 187 71 88 0 149 3 107 134 40 236 20 146 153 68 234 28 55 243 232 89 212 57 36 98 161 163 175 172 9 59 12 4 128 20 247 210 243 85 83 234 85 129 212] :uuid "39f4368b-5a80-534b-964d-dffbb5f1022a"}
   {:edn [199 191 250 58 81 41 226 253 255 176 97 217 238 34 1 115 47 74 133 110 180 144 221 232 136 47 231 177 251 179 232 122 209 88 169 32 17 82 236 135 148 172 231 137 235 139 227 76 180 125 183 138 236 199 6 51 144 20 143 220 57 155 96 162] :uuid "07bffa3a-5129-52fd-bfb0-61d9ee220173"}])

(deftest corpus-count-matches
  (is (= (count corpus) (count expected))
      "corpus and expected must stay in lock-step"))

(deftest edn-hash-identity
  (testing "edn-hash is bit-identical to hasch 0.3.94 for every corpus value"
    (doseq [[i v exp] (map vector (range) corpus expected)]
      (is (= (:edn exp) (vec (edn-hash v)))
          (str "edn-hash mismatch at corpus index " i " -> " (pr-str v))))))

(deftest uuid-identity
  (testing "uuid (uuid5 of edn-hash) is bit-identical to hasch 0.3.94"
    (doseq [[i v exp] (map vector (range) corpus expected)]
      (is (= (:uuid exp) (str (uuid v)))
          (str "uuid mismatch at corpus index " i " -> " (pr-str v))))))

(deftest map-order-independence
  (testing "maps still hash order-independently (commutative)"
    (is (= (vec (edn-hash {:system "http://loinc.org" :code "1234-5" :display "Body Weight"}))
           (vec (edn-hash {:display "Body Weight" :code "1234-5" :system "http://loinc.org"}))))))

(deftest map-implementation-independence
  (testing "every IPersistentMap implementation hashes identically:
            array-map (IKVReduce), hash-map (IKVReduce), sorted-map
            (IKVReduce via tree nodes), struct-map (NOT IKVReduce — takes the
            seq-walk fallback in xor-map-hashes)"
    (let [m {:a 1 :b "two" :c :three :d [4] :e {:f 5} :g nil :h 7 :i 8 :j 9 :k 10}
          expect (vec (edn-hash m))]
      (is (= expect (vec (edn-hash (into (sorted-map) m)))))
      (is (= expect (vec (edn-hash (apply array-map (mapcat identity m))))))
      (is (= expect (vec (edn-hash (into (hash-map) m))))))
    (is (= (vec (edn-hash (struct-map (create-struct :a :b) :a 1 :b 2)))
           (vec (edn-hash {:a 1 :b 2}))))))

(deftest set-order-independence
  (testing "sets still hash order-independently (commutative)"
    (is (= (vec (edn-hash #{1 2 3 4 5}))
           (vec (edn-hash #{5 4 3 2 1}))))
    (is (= (vec (edn-hash #{"Fred" "Freddy" "F-Dog"}))
           (vec (edn-hash (into (sorted-set) #{"Fred" "Freddy" "F-Dog"})))))))

(deftest datomic-entity-shape
  (testing "cardinality-many attributes (set values inside entity maps) —
            pinned from hasch 0.3.94"
    (is (= "050ff8ed-11ff-51fd-8a4a-dd50b1c0ba7a"
           (str (uuid {:person/name "Frederic"
                       :person/aliases #{"Fred" "Freddy" "F-Dog"}
                       :person/tags #{:vip :beta-tester}}))))))

(deftest md5-identity
  (testing "non-default digest fn: maps/sets XOR-truncate to min(hash-len, 32),
            i.e. 17/16 bytes for MD5, not 32 — pinned from hasch 0.3.94"
    (let [eh (fn [v] (vec (edn-hash v md5-message-digest {})))]
      (is (= [116 147 199 146 30 118 41 253 35 9 21 203 165 85 154 134]
             (eh {:a 1})))
      (is (= [84 178 138 159 166 208 146 173 164 61 47 12 20 142 171 70]
             (eh {:system "http://loinc.org" :code "1234-5" :display "Body Weight"})))
      (is (= [158 238 167 195 119 21 121 96 75 93 58 123 84 206 143 87]
             (eh #{1 2 3})))
      (is (= [104 179 41 218 152 147 227 64 153 199 216 173 92 185 201 64]
             (eh {})))
      (is (= [19 200 255 217 119 1 55 3 167 1 207 142 17 222 172 101]
             (eh #{})))
      (is (= [20 19 49 228 186 168 42 218 226 107 173 243 196 25 146 62]
             (eh {:person/name "Frederic" :person/aliases #{"Fred" "Freddy"}}))))))
