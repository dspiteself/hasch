# hasch allocation analysis & reduction (`perf/reduce-allocations`)

**Baseline:** hasch `0.3.94` (tag `0.3.94`, commit `d9efe49`) + incognito `0.3.66`.
**Branch:** `perf/reduce-allocations` (forked from `0.3.94`).
**Scope:** JVM hot path (`platform.clj` + `benc.cljc`). All changes keep the hash
output **bit-identical** to 0.3.94 — verified by a pinned-hash corpus, the existing
`api_test`, and the datahike integration test (see [Hash identity](#hash-identity)).

## Why this matters

hasch 0.3.94 is on the **Datomic transactor** classpath so the `:coding/add` and
`:codeableconcept/add` `:db/fns` in `fhir-store-datomic` can content-hash
Coding/CodeableConcept entities *inside the transactor JVM on every write*. During
the FHIR "decant" (~2.4M source transactions, each with many Codings/CodeableConcepts)
`hasch/uuid` runs constantly in a `-Xmx5500m` JVM with small Datomic cache settings,
so its allocation churn is a direct GC-pressure lever (the transactor was recently
OOM-killed). The transactor calls the **`uuid` path** (`edn-hash` → `uuid5`), which
is exactly where the largest wins land.

---

## 1. The hot path (hashing a Coding / CodeableConcept)

For a Coding `{:system "…" :code "…" :display "…"}`:

```
core/uuid
└─ edn-hash-bytes                                  ; -coerce then final digest
   └─ -coerce {IPersistentMap}                     ; platform.clj
      ├─ (seq m)                                    ; lazy seq over 3 MapEntries
      ├─ (map -coerce entries)                      ; lazy seq of per-entry byte[]
      │   └─ per MapEntry  → -coerce {IPersistentVector}   (MapEntry IS an IPersistentVector!)
      │        └─ coerce-seq [k v]                  ; **NEW MessageDigest**, then:
      │             ├─ -coerce k {Keyword}          ; str→utf8, encode-safe, encode
      │             └─ -coerce v {String}           ; str→utf8, encode-safe, encode
      │             └─ .digest                       ; 64-byte array
      │        └─ encode(:vector, digest)           ; +1 magic byte → 65-byte array
      ├─ xor-hashes                                  ; XOR first 32 bytes of each entry
      └─ encode(:map, xor)                           ; +1 magic byte
   └─ digest(map-bytes)                             ; **NEW MessageDigest** → 64-byte hash
core/uuid5-bytes → ByteBuffer → java.util.UUID
```

### Allocation hotspots found (measured on JDK 25, `getThreadAllocatedBytes`)

| # | Hotspot | Where | Cost |
|---|---------|-------|------|
| 1 | **`(map #(if (neg? %) (+ % 256) %) …)` unsigned lazy seq** over 64 digest bytes, realized by `uuid5`/`byte-array`/`b64` | `core/edn-hash` | **7,832 B/op** |
| 2 | **`MessageDigest/getInstance` per collection/seq/map-entry** — 384 B object + synchronized provider lookup | `benc/digest`, `benc/coerce-seq` | 384 B × **4 (Coding)** / **10 (CodeableConcept)** |
| 3 | **`encode` via `ByteArrayOutputStream`** to prepend a 1-byte magic (1-byte array + growable buffer + `toByteArray` copy) | `platform/encode` | ~135 B/call, ~10 calls/Coding |
| 4 | **`encode-safe` via `ByteArrayOutputStream`** to concat `a ++ escape-markers` (extra `ea` array + stream buffer + copy) | `benc/encode-safe` | per string/keyword/symbol |
| 5 | `byte-array` rebuild of the unsigned seq in `uuid5` | `platform/uuid5` | 80 B/op |
| 6 | `.getBytes "UTF-8"` charset-**name** lookup per call | `platform/str->utf8` + number/uuid/date encoders | time (charset lookup) |
| 7 | Reflection | — | none (`*warn-on-reflection*` already clean) |

Number of `MessageDigest` instances created per value (measured): **Coding = 4,
CodeableConcept = 10, Observation ≈ 13.**

---

## 2. Baseline vs optimized (fresh JVM each, identical harness)

`uuid …` is the transactor's path; `edn-hash … (realized)` forces the returned seq
(what direct callers do). Harness: warmup + `System/gc`, then N iterations timed with
`System/nanoTime` and allocation via `com.sun.management.ThreadMXBean`.

Final numbers with all shipped changes (C1, C3–C8; the C2 pool was prototyped,
measured, and **dropped by decision** — see C2 below):

| Case | Baseline B/op | Optimized B/op | **Δ alloc** | Baseline ns | Optimized ns | Δ time |
|------|--------------:|---------------:|:-----------:|------------:|-------------:|:------:|
| **uuid Coding** | 14,264 | 2,504 | **−82 %** | 4,319 | 1,198 | −72 % |
| **uuid CodeableConcept** | 23,488 | 6,776 | **−71 %** | 6,963 | 2,866 | −59 % |
| **uuid Observation** | 30,680 | 9,864 | **−68 %** | 9,291 | 4,134 | −56 % |
| **uuid cc-batch (20×CC)** | 301,744 | 128,248 | **−57 %** | 90,735 | 51,565 | −43 % |
| **uuid bigmap (200 entries)** | 346,912 | 130,200 | **−62 %** | 104,080 | 62,191 | −40 % |
| **uuid entity (card-many sets)** | 24,640 | 8,808 | **−64 %** | 8,061 | 3,654 | −55 % |
| **uuid bigset (200 elems)** | 198,176 | 117,456 | **−41 %** | 77,392 | 52,168 | −33 % |
| **b64-hash Coding** | 14,560 | 2,800 | **−81 %** | 4,385 | 1,110 | −75 % |
| **b64-hash CodeableConcept** | 23,688 | 6,976 | **−71 %** | 6,995 | 2,878 | −59 % |
| edn-hash Coding (realized) | 14,152 | 11,112 | −21 % | 3,702 | 2,979 | −20 % |
| edn-hash CodeableConcept (realized) | 23,376 | 15,144 | −35 % | 6,456 | 4,660 | −28 % |

"entity" is a Datomic-style entity map with three cardinality-many SET values —
sets have no intrinsic order in Datomic, so this shape hits the set branch on
every entity hash. Intermediate per-change numbers in the sections below were
mostly measured on pool-inclusive builds and are noted as such where they
differ.

The `uuid` path benefits from *all* changes (incl. the lazy-seq bypass); the direct
`edn-hash` path keeps its public unsigned-seq return, so it only gets the
`encode`/`encode-safe` + fusion savings (still −21…35 %).

Reproduce: `clojure -M:bench` (see `dev/bench.clj`); for the baseline column point
the classpath at a `0.3.94` src checkout (command documented in `dev/bench.clj`).

---

## 3. Changes made (each bit-identical)

All changes preserve the pre-digest byte encoding exactly; SHA-512 makes any
accidental divergence detectable via the pinned corpus.

### C1 — Bypass the unsigned lazy-seq + `byte-array` round-trip on the `uuid` path
`core/edn-hash` returns `(map make-unsigned raw-digest)`. `uuid5` then did
`(byte-array that-seq)`, and `(byte-array (map make-unsigned raw)) == raw` exactly
(the unsigned map + `byte-array` unchecked-cast cancel out). New private
`core/edn-hash-bytes` returns the raw signed digest array; `platform/uuid5-bytes`
consumes it directly through the `ByteBuffer`. `uuid` uses this fast path.
`edn-hash` and `uuid5` keep their exact public behaviour (`uuid5` still accepts the
unsigned seq — `api_test` relies on that). **Saves hotspot #1 + #5 on the uuid path.**

### C2 — Thread-local `MessageDigest` free-list — **prototyped, measured, DROPPED**
`MessageDigest.digest()` leaves the instance reset, so it is immediately
reusable. The prototype had `digest`/`coerce-seq`/`map-entry-digest` borrow from
a per-thread free-list (`ThreadLocal<IdentityHashMap<factory, ArrayDeque>>`)
and return instances after `.digest`. It was verified safe (0 mismatches across
~1.18M concurrent `uuid` computations on 16 threads; nested digests each borrow
a distinct instance; exception → instance dropped; keyed by `md-create-fn`
identity so SHA-512/MD5 never mix) and bit-identical. **It was dropped by
decision** to keep the branch free of thread-local state and to keep
`md-create-fn` invoked exactly once per digest — hotspot #2 therefore remains
in the shipped branch, at one fresh `MessageDigest` per collection/entry.

**Ablation — what the pool would add on top of the shipped branch** (kept on
record as the obvious next lever if transactor GC pressure needs another turn;
the full implementation is preserved on the `archive/perf-with-md-pool` branch):

| `uuid` case | shipped (no pool) | with pool | pool's further B/op cut | pool's time cut |
|---|--:|--:|:--:|:--:|
| Coding | 2,600 B / 999 ns | 1,064 B / 1,049 ns | −59 % | ≈0 |
| CodeableConcept | 6,776 B / 2,979 ns | 2,936 B / 2,625 ns | −57 % | −12 % |
| cc-batch (20×CC) | 128,248 B / 52,848 ns | 58,360 B / 46,175 ns | −54 % | −13 % |
| bigmap (200) | 130,200 B / 58,562 ns | 59,416 B / 59,046 ns | −54 % | ≈0 |
| entity (card-many sets) | 8,808 B / 3,811 ns | 3,432 B / 3,370 ns | −61 % | −12 % |
| bigset (200) | 117,456 B / 56,599 ns | 40,272 B / 41,610 ns | −66 % | −26 % |

With the pool, allocations drop a further 2.2–2.9× — a SUN SHA-512
`MessageDigest` is ~400–600 B of internal state, and the fused map/set paths
create one per entry/element, so per-entry MD allocation (plus the synchronized
`getInstance` provider lookup, ~40 ns) is the dominant remaining cost in the
shipped branch. Pool trade-offs if revisited: per-thread retention bounded by
max value nesting (single-digit KB); semantic surface is that `md-create-fn`
gets invoked fewer times (any factory returning a standard `MessageDigest` is
unaffected — `.digest` resets the instance, which is the documented contract).

### C3 — `encode` without `ByteArrayOutputStream` (`platform/encode`)
Prepend the magic byte in one allocation: `byte-array(1+len)`, set `[0]=magic`,
`System/arraycopy` the payload. Byte-identical to the old `BAOS(magic, a)`.
**Removes hotspot #3.**

### C4 — `encode-safe` single-array (`benc/encode-safe`, JVM only)
The old code built an `ea` marker array then `BAOS(a, ea)`. New JVM path allocates
one `byte-array(2·len)`, copies `a` into the low half, and writes the `1` markers
directly into the (zero-initialised) high half. Byte-identical. The **ClojureScript
branch is left exactly as before** (`ea` + `.concat`). **Removes hotspot #4.**

### C5 — `StandardCharsets/UTF_8` instead of `"UTF-8"`
`str->utf8` and the number/uuid/inst encoders now pass the `Charset` object rather
than the charset *name*, avoiding a per-call charset lookup. Same UTF-8 bytes.
**Addresses hotspot #6.**

### C6 — Public `edn-hash-bytes` + `b64-hash` fast path
`edn-hash-bytes` is now a **public, additive** API returning the raw digest
platform-natively (signed `byte[]` on JVM, unsigned array on cljs) with the same
convenience arities as `edn-hash`. The digest bytes are exactly `edn-hash`'s —
only the container differs — so hashes remain interchangeable; callers must just
remember JVM byte arrays use identity equality. `b64-hash` now encodes it
directly instead of rebuilding an array from the unsigned seq (identical base64
string, pinned by `api_test` on both platforms). `edn-hash` itself is untouched.
New hot-path consumers (e.g. transactor `:db/fns` wanting the full 512-bit
address rather than the UUID) should call `edn-hash-bytes`/`b64-hash`/`uuid`,
none of which touch the unsigned seq anymore.

### C7 — Fused map XOR via `reduce-kv` (`platform/xor-map-hashes`)
The map branch previously built, per entry: a `MapEntry` + seq node (from
`(seq m)` / `map`), a fresh 65-byte `encode(:vector, sha512(k·v))` array and a
lazy-seq cell — all just to be XOR-folded into 32 bytes and discarded. Now each
entry's digest is folded straight into the 32-byte accumulator (byte 0 XORs the
`:vector` magic `9`, bytes 1–31 XOR `digest[0..30]`), visiting entries with
**`reduce-kv`** — the map's internal `IKVReduce` reduce, which iterates without
allocating seq nodes or `MapEntry`s. XOR is commutative so visit order is
irrelevant; `{}` still yields `(byte-array 0)`. Non-`IKVReduce` maps (e.g.
`struct-map`) take a seq-walk fallback — hinted as **`IMapEntry`, not
`MapEntry`**, because sorted-map seqs yield tree-node entries that are not
`MapEntry` instances (found the hard way; pinned in
`map-implementation-independence`).

Both fusion strategies were raced in fresh JVMs (each passing the pinned
corpus with the variant installed):

| `uuid` case | pre-C7 (lazy seq + `xor-hashes`) | fused, **seq loop** | fused, **`reduce-kv`** |
|---|--:|--:|--:|
| Coding | 2,752 B / 1,651 ns | 1,256 B / 1,012 ns | **1,064 B / 947 ns** |
| CodeableConcept | 7,472 / 4,159 | 3,448 / 2,664 | **3,032 / 2,638** |
| Observation | 11,384 / 6,195 | 4,936 / 3,895 | **4,232 / 3,785** |
| bigmap (200) | 176,200 / 94,764 | 83,296 / 60,985 | **59,368 / 50,942** |
| sorted-map (200) | 166,696 / 100,505 | 73,792 / 68,102 | **59,368 / 55,802** |

`reduce-kv` wins across the board; the loop-vs-rkv gap is pure seq machinery
(~120 B/entry of seq nodes + `MapEntry`s on the 200-entry map). ClojureScript
keeps the original seq-based path unchanged.

**Bug found & fixed during C8:** the first C7 cut hardcoded the 32-byte
accumulator, which is only right for SHA-512. The generic `xor-hashes` sizes it
as `min(count(first-hash), 32)` — 17 bytes for MD5 map entries — so maps hashed
with `md5-message-digest` threw `ArrayIndexOutOfBoundsException`. Fixed by
sizing the accumulator off the first entry's digest (`min(1+dlen, 32)`), and
`md5-identity` now pins 0.3.94's MD5 hashes for maps/sets so the non-default
digest path can't regress silently again.

### C8 — Fused set XOR (`platform/xor-set-hashes`)
Datomic cardinality-many attributes surface as **sets** in entity maps (no
intrinsic order), so the set branch is hot for transactor workloads too. Same
fusion as C7: each element's digest XORs straight into a `min(dlen, 32)`-byte
accumulator (set element hashes carry no magic prefix, unlike map entries).
Sets implement neither `IKVReduce` nor `IReduceInit`, but `reduce` walks them
via their internal iterator (CollReduce's `Iterable`/`iter-reduce`) — no seq
nodes. `#{}` still yields `(byte-array 0)`.

| `uuid` case | 0.3.94 | fused | Δ |
|---|--:|--:|:--:|
| entity (3 card-many sets) | 24,640 B / 8,061 ns | **3,432 B / 3,370 ns** | −86 % / −58 % |
| bigset (200 strings) | 198,176 B / 77,392 ns | **40,272 B / 41,610 ns** | −80 % / −46 % |

**Clojure compiler gotcha documented in the code:** `(defn ^bytes f …)` return
tags are evaluated by `def`, so the var `:tag` becomes the `clojure.core/bytes`
*function object*; any call site that consults the callee's tag (e.g. binding
the result to a symbol-hinted local and calling `alength`) fails to compile.
hasch's own `digest`/`coerce-seq`/`encode` defns carry these poisoned tags and
survive only because no call site consults them. The fused helpers therefore
keep all array interop on `^bytes` *params* and hint *expressions* (form
metadata overrides the var tag) where needed.

---

## 4. Hash identity

Regression guard: `test/hasch/identity_test.clj` pins `edn-hash` (unsigned-byte
vector) **and** `uuid` (string) for a 37-value corpus captured from unmodified
0.3.94 — primitives, strings, keywords, symbols, numbers, nil, uuid, inst,
empty/typed collections, sets, maps, plus the FHIR shapes (Coding, CodeableConcept,
nested Observation) and an incognito tagged-literal (record path). It also checks
map/set order-independence.

It further asserts map *implementation* independence (array-map, hash-map,
sorted-map, struct-map — the last exercising the non-`IKVReduce` fallback), the
Datomic entity shape with cardinality-many set values, and MD5 (non-default
digest) hashes for maps/sets — all pinned from unmodified 0.3.94.

| Suite | Result |
|-------|--------|
| `hasch.identity-test` (new pinned corpus, incl. MD5 + entity shapes) | **0 failures** |
| `hasch.api-test` (existing pins, JVM) | **0 failures** |
| `clojure -M:test` (unit + integration incl. datahike) | **16 tests, 121 assertions, 0 failures** |
| `shadow-cljs compile node-test` + `hasch.api-test` (cljs) | **0 warnings; 8 tests, 27 assertions, 0 failures** |
| `clojure -M:format` (cljfmt) | clean |
| Concurrency stress (16 threads, ~0.6–1.2M `uuid` per run, after each change set incl. final no-pool build) | **0 mismatches** |

`tests.edn` now also defines a `:unit` suite (was integration-only) so
`clojure -M:test` exercises the unit tests including the new pins.

---

## 5. Wins that would change the hash (upstream-worthy, **NOT** done)

These reduce allocation further but **alter the output bytes**, so they would break
every stored content-address and are out of scope for this branch. Flagged for
upstream discussion:

- **Numbers hashed as decimal strings.** Each number allocates a `String`
  (`.toString`) + its UTF-8 bytes. A fixed binary encoding (e.g. 8 raw bytes per
  `long`) would allocate less and be faster, but **changes the hash**. *Risky.*
- **Per-entry `MessageDigest` for maps is intrinsic to the current hash.** The map
  hash is `XOR( encode(:vector, sha512([k v])) )`; the SHA per entry cannot be
  removed without redefining the map hash. *Risky.*
- **Changing `edn-hash` itself to return `byte[]`.** The additive `edn-hash-bytes`
  (C6) already lets every caller opt out of the unsigned seq, and all in-repo
  consumers (`uuid`, `b64-hash`) now bypass it. Going further — making `edn-hash`
  *return* the raw array — would not change any hash bytes, but it breaks the
  API contract: results lose value equality (`=` on JVM arrays is identity), and
  every existing pin/consumer comparing `(= (edn-hash x) '(184 36 …))` (including
  hasch's own `api_test`) would fail. That is a major-version upstream decision;
  with C6 in place it buys nothing further for hasch-internal paths.

## 6. Further safe wins not yet taken

- **The C2 MessageDigest pool** — measured, bit-identical, and dropped by
  decision (see C2). Reinstating it is the single biggest remaining lever:
  a further −54…66 % B/op on every digest-heavy shape.
- **`clone()` a template MessageDigest** instead of `getInstance` per digest —
  `clone` (13 ns) vs `getInstance` (42 ns) and no provider lookup; a milder,
  stateless alternative to the pool that would need the same
  `md-create-fn`-keyed template cache.
- **Replace the poisoned `^bytes` defn tags** on `digest`/`coerce-seq`/`encode`/
  `encode-safe` with `^"[B"` string tags (which `def` evaluates to themselves).
  Purely defensive — see the compiler gotcha under C8.
