# V3 implementation audit — 2026-09-09

## Scope and validation

Reviewed the Rust crate’s current v3 implementation, which resides primarily in `logfs/src/journal/v2`, plus its shared crypto, public API, and existing tests. Legacy v2 was considered only where its shared machinery affects v3. CLI behavior, dependency vulnerability scanning, and unrelated design plans were outside scope. No source code was changed.

`cargo test -p logfs --locked` passed: **45 unit tests and 2 integration tests**, with no failures; there were no doc tests. Findings below are confirmed from source, not new executable reproductions. Review stopped at the requested handoff; this is a substantive, bounded audit, not an exhaustive security certification.

The implementation has strong authentication and commit-boundary checks. The principal concerns found are recovery availability, two stale framing calculations, and inconsistent writer/reader resource limits. Existing passing tests do not exercise all of those boundaries.

## Confirmed issues

### 1. High: one damaged root blocks both opening and explicit repair

Normal opening authenticates both v3 root slots and propagates a failure from either before selecting a generation (`logfs/src/journal/v2/read.rs:154`, `logfs/src/journal/v2/read.rs:166`, `logfs/src/journal/v2/read.rs:173`). Both must also have matching identity, secret, salts, and adjacent generations (`logfs/src/journal/v2/read.rs:250`). This intentionally prevents silently choosing older state when a root is damaged.

However, repair calls that same strict root reader before searching for recoverable records (`logfs/src/journal/v2/repair.rs:29`). A torn root overwrite therefore prevents explicit salvage even when the other root authenticates and contains the secret needed to decrypt intact records. Root publication overwrites a slot through ordinary file writes (`logfs/src/journal/v2/write.rs:571`); ordered synchronization does not establish atomicity of a 4 KiB overwrite. Physical truncation can also stop repair at root validation because a committed tail beyond EOF is rejected (`logfs/src/journal/v2/read.rs:47`).

Impact: a damaged root or truncated committed tail can make all otherwise recoverable values inaccessible through the crate’s repair API. The existing root-corruption test explicitly checks that normal opening rejects damaged roots (`logfs/src/lib.rs:1347`), but does not establish recovery from them.

Recommendation: retain strict normal opening, but give explicit repair a separate bootstrap path that can authenticate a surviving root, report uncertainty about the latest committed state, and export verified records to a fresh destination. This is a recovery-policy decision, not a recommendation to silently weaken normal authentication.

### 2. Medium: repair’s scan overlap is 232 bytes too short for v3 headers

The v3 scanner searches buffers of at most 100,000 bytes (`logfs/src/journal/v2/repair.rs:63`). Its overlap calculation uses a 24-byte nonce plus `JournalEntryHeader::SERIALIZED_LEN`, which is 24 bytes, plus authentication/checksum padding (`logfs/src/journal/v2/repair.rs:103`, `logfs/src/journal/v2/data.rs:259`). Actual v3 framing uses a **256-byte** clear header (`logfs/src/journal/v2/mod.rs:1301`).

For encrypted logs, the complete searchable header is 24 + 256 + 16 = 296 bytes, requiring 295 bytes of overlap. Repair retains only 63. For plaintext, it retains 79 instead of 311. In both cases, 232 possible header-start positions near a scan boundary are missed: the current buffer cannot contain the whole header, and the next buffer starts after its beginning.

Impact: locating a requested sequence can fail solely because its valid header straddles a scan boundary. This is relevant when recovering from a later sequence or from a region at a nonzero offset. The default first record of a zero-offset log does not encounter that boundary.

Recommendation: derive overlap from the same complete v3 frame-header size used by the parser. Add boundary cases immediately before, at, and after the scanner’s buffer transition.

### 3. Medium: bounded-write preflight undercounts every v3 entry by 248 bytes

The initial whole-entry capacity calculation uses an 8-byte v3 domain and the 24-byte legacy header (`logfs/src/journal/v2/write.rs:627`, `logfs/src/journal/v2/write.rs:634`). Actual writing uses a 24-byte nonce and a 256-byte clear header (`logfs/src/journal/v2/write.rs:782`, `logfs/src/journal/v2/write.rs:814`). The preflight therefore underestimates required space by **16 + 232 = 248 bytes**.

There is a later, correctly sized metadata capacity check (`logfs/src/journal/v2/write.rs:819`), and capacity enforcement rejects writes past the configured region (`logfs/src/journal/v2/write.rs:361`). This finding is not an established out-of-region write. The defect is that an entry which passes the supposed whole-entry preflight can fail inside the write operation. That error taints the writer (`logfs/src/journal/v2/write.rs:647`), even where a correct preflight could reject the oversized operation before entering the mutation path. If metadata fits but the value does not, an unpublished partial entry may already have been written.

Impact: a predictable capacity error can unnecessarily disable further writes until reopen, including smaller operations that could fit. Existing region tests cover overflow rejection and surrounding-byte preservation (`logfs/src/lib.rs:1514`), not all exact-fit and continued-usability cases.

Recommendation: centralize v3 encoded-size calculation and use it for both reservation and emission. Test exact fit, one byte short, and a subsequent smaller mutation after a rejected oversized insert.

### 4. Medium: writers can publish metadata that readers reject for exceeding limits

The reader rejects an encoded action larger than 512 MiB before allocation (`logfs/src/journal/v2/read.rs:523`). The writer serializes the action and checks only that its encoded length fits `u32` (`logfs/src/journal/v2/write.rs:724`, `logfs/src/journal/v2/write.rs:753`). It does not enforce the reader’s smaller limit. A sufficiently large key name or batch can therefore be accepted and committed but subsequently fail replay when that action must be read. A later usable checkpoint may bypass it, so this is not an unconditional failure on every reopen.

There is also a narrow checkpoint boundary mismatch: the writer permits a serialized checkpoint of exactly 512 MiB (`logfs/src/journal/v2/write.rs:963`), while the reader applies its payload cap to the length including encryption padding (`logfs/src/journal/v2/read.rs:581`, `logfs/src/journal/v2/read.rs:603`). Encrypted snapshots within the top 16 bytes of the writer’s permitted range cannot be restored through the checkpoint path; opening attempts full replay instead (`logfs/src/journal/v2/mod.rs:925`).

Impact: writer/reader disagreement can produce successful operations that degrade or prevent subsequent opening. The action case requires unusually large caller input; it is a correctness and resource-boundary issue, not a demonstrated unauthenticated attack against encrypted files.

Recommendation: share limits and distinguish plaintext, encoded, and decoded lengths explicitly. Check serialized size before constructing large buffers. The checkpoint writer currently checks its limit only after allocating the serialized snapshot and its temporary key collection (`logfs/src/journal/v2/write.rs:934`, `logfs/src/journal/v2/write.rs:963`).

## Crypto assessment

**No confirmed cryptographic primitive misuse, practical nonce-reuse exploit, or encrypted authentication bypass was found in the reviewed paths.** Password keys use bounded Argon2id profiles: Standard is 64 MiB and LowMemory is 8 MiB, both with three passes and one lane (`logfs/src/crypto.rs:38`). Each root has an independent random salt; root keys are additionally separated by physical slot through HKDF (`logfs/src/crypto.rs:113`). The random per-log secret is expanded into separate root, entry, checkpoint, and history keys (`logfs/src/crypto.rs:280`).

Entry seeds come from the system RNG (`logfs/src/journal/v2/write.rs:585`). The chunk number is XORed into the final four bytes of the seed (`logfs/src/journal/v2/mod.rs:1344`); for a fixed entry this is injective. Associated data binds file identity, the original entry seed, and chunk number (`logfs/src/journal/v2/mod.rs:1354`). History commitments include the preceding commitment and serialized action (`logfs/src/journal/v2/mod.rs:1324`), and normal replay validates the predecessor and recomputed commitment (`logfs/src/journal/v2/read.rs:490`, `logfs/src/journal/v2/read.rs:565`).

Tests cover purpose/file key separation, cross-file ciphertext substitution, sibling-history splicing, wrong credentials, and root-slot substitution (`logfs/src/crypto.rs:406`, `logfs/src/lib.rs:1299`, `logfs/src/lib.rs:2236`, `logfs/src/lib.rs:2200`, `logfs/src/lib.rs:2219`). Plaintext checksums detect corruption but do not provide adversarial authenticity. Whole-value hash checking is deliberately optional for routine reads; encrypted chunk authentication remains mandatory (`logfs/src/journal/v2/read.rs:904`, `logfs/src/journal/v2/read.rs:944`).

Optional improvements: document the nonce collision budget across large, multi-chunk histories; keep named KDF profiles immutable as the format evolves; and reduce transient secret copies. Passwords and retained secrets use zeroizing wrappers, but decrypted root buffers and bootstrap-secret arrays are ordinary allocations/arrays (`logfs/src/journal/v2/read.rs:163`, `logfs/src/journal/v2/read.rs:178`). `V3RootPayload` also derives `Debug` while containing the raw secret (`logfs/src/journal/v2/mod.rs:1411`). No actual logging of that payload was established; remove or redact that capability as preventive hardening.

## Disk-format evolution and future-proofing

The fixed root slots, authenticated version/profile, generation checks, explicit frame lengths, and committed history boundary are useful foundations (`logfs/src/journal/v2/mod.rs:1291`, `logfs/src/journal/v2/mod.rs:1412`). No additional confirmed format-integrity defect was identified beyond the issues above. Restoring an entire older authenticated snapshot still requires external trusted state to detect; it is outside the local substitution protections.

Optional improvements before treating v3 as frozen:

- Publish a byte-level format specification and independent golden fixtures. Current v3 tests largely exercise the current implementation against itself; freeze representative plaintext/encrypted roots, entries, empty values, and checkpoints.
- Freeze explicit wire identifiers and field semantics. On-disk structures use Serde/bincode, including declaration-order enums for actions and crypto profiles (`logfs/src/journal/v2/data.rs:179`, `logfs/src/crypto.rs:28`). Reordering variants or fields can silently alter the format even when the Rust change looks harmless.
- Define required versus optional features and unknown-record handling. Root opening currently requires version 3 exactly (`logfs/src/journal/v2/read.rs:211`); bounded deserialization permits trailing bytes (`logfs/src/journal/v2/mod.rs:405`). Those choices need an explicit compatibility contract, not ad hoc future extensions.
- Specify offset coordinates. V3 checkpoints persist absolute backing-file offsets (`logfs/src/journal/v2/write.rs:941`), while entry offsets are relative to the region (`logfs/src/journal/v2/write.rs:722`). Relocating a region therefore requires export/rewrite or deliberate pointer translation; document this before promising portable region images.

## Recovery, security, and code quality

Durable publication orders record flush/sync before root publication and root sync (`logfs/src/journal/v2/write.rs:598`). Checkpoint failure resets state and rewinds before full replay (`logfs/src/journal/v2/mod.rs:936`). Recovery exports to an exclusively created destination, verifies copied values, then reopens and verifies the output (`logfs/src/journal/v2/repair.rs:317`, `logfs/src/journal/v2/repair.rs:332`, `logfs/src/journal/v2/repair.rs:368`). These are sound safeguards within the root-bootstrap limitation above. No additional confirmed locking or publication-order bug was found in the reviewed paths.

Optional organization work: separate the v3 codec and root/recovery policy from legacy compatibility, give frame sizes and resource limits a single definition, and use typed corruption/resource errors instead of predominantly internal-error strings. The two stale-size defects demonstrate a concrete maintenance cost of duplicating v3 framing across shared modules. Keep this refactor separate from behavior fixes.

Resource limits also need more precise documentation: bounding encoded/decoded bytes does not cap total working memory when buffers, deserialized collections, tree nodes, and encrypted-chunk copies coexist (`logfs/src/journal/v2/read.rs:898`, `logfs/src/journal/v2/read.rs:914`, `logfs/src/journal/v2/mod.rs:602`). Treat tighter allocation budgets and parser fuzzing as optional hardening; no encrypted-file allocation exploit was demonstrated in this review.

Prioritize explicit salvage from damaged roots, then fix the two framing calculations and unify writer/reader limits. Preserve the existing authentication and history checks while adding tests for those specific boundaries.

## Implementation status — 2026-09-09

The findings above are preserved as the original audit, including their historical paths and line numbers. The implementation now lives in `logfs/src/journal/v3`; the old `v2` module retains legacy decoding/checkpoint logic and compatibility re-exports. Shared action types and bounded decoding helpers live directly under `journal`. Public API names, including `Journal2`, remain compatible. No on-disk layout, key derivation context, nonce schedule, or normal-open history check was changed.

### Completed

- **Finding 1:** Explicit repair has its own root-bootstrap policy. It can authenticate/checksum one surviving slot and accept a committed tail beyond EOF for salvage. Strict normal open still requires both consistent, adjacent roots and valid committed boundaries. Conflicting authenticated root pairs remain an error. Repair logs uncertainty about the latest committed state and continues to export verified values into a fresh destination.
- **Finding 2:** Scanner overlap derives from the complete v3 header (24-byte seed + 256-byte clear header + tag/checksum), giving 295 encrypted or 311 plaintext overlap bytes. Candidate authentication avoids constructing an error/backtrace at every rejected byte position; normal reads retain diagnostic errors.
- **Finding 3:** A central frame-size formula includes the previously missing 248 bytes. Ordinary insert preflight and streaming metadata reservation check bounds before mutation; predictable rejection leaves the writer usable. Streaming reserves room for the minimum empty encrypted chunk tag. Actual I/O or midstream failures still taint the writer.
- **Finding 4:** Shared v3 action/checkpoint plaintext limits are 512 MiB; encoded limits separately include authentication overhead. Writer measurement precedes serialization, read-buffer limits precede allocation, and decoded checkpoint limits remain bounded by committed region length and the implementation budget. The snapshot serializer borrows the key tree, measures it before allocation, and preserves the original owned bincode layout.
- **Organization:** Dedicated v3 `format`, `root`, `index`, `limits`, `read`, `write`, and `repair` modules. Legacy root/entry decoding and parented checkpoint restoration are in `v2/codec.rs` and `v2/index.rs`; the v3 writer rejects legacy writes. Read adapters retain explicit version dispatch for the public API.
- **Secret hygiene:** Removed raw-root-payload Debug support, zeroized root-payload secrets on drop, wrapped decrypted root/bootstrap/serialization buffers, and returned HKDF expansions in zeroizing wrappers. This reduces ordinary transient secret allocations without promising elimination of every compiler copy.
- **Specification:** Added [`docs/v3-format.md`](../v3-format.md), covering byte layouts, actual bincode enum ordinals, coordinates, envelopes, KDF/AEAD domains, framing, snapshots, commit/recovery policy, resource limits, and evolution rules. The distinction between strict replay, salvage, and metadata-only dry-run is explicit.
- **Regression coverage:** Both damaged root slots in plaintext/encrypted modes, wrong credentials and both roots damaged, truncated committed tails, scan-boundary starts at nonzero region offsets, exact-fit and one-byte-short writes with surrounding-byte preservation, post-rejection writer reuse, streaming reservation rejection, action writer/replay/repair agreement, direct checkpoint restoration at its budget, production limit arithmetic, and frozen wire layout/discriminant assertions.

### Recommendations intentionally deferred

- New public corruption/resource-limit error variants: `LogFsError` is exhaustively matchable; adding variants could break callers. Existing variants now carry explicit v3 length/budget diagnostics.
- New required/optional feature bits, hand-written enum codecs, and new unknown-record behavior: these require a compatibility design, rather than a behavior-changing v3 refactor. The specification freezes current ordinals and distinguishes permissive decoding from a supported extension contract.
- Complete-file plaintext/encrypted golden images and an independent decoder: the added hand-built byte assertions pin key layouts and discriminants; a comprehensive independent fixture corpus remains additional work.
- Sustained parser fuzzing and aggregate allocation budgets: focused deterministic boundary tests are included, but encoded/decoded byte caps are not a total-memory accounting system. That work needs separate infrastructure and workload decisions.
- Automatic key rotation / a lifetime nonce counter: the current random-seed schedule is retained; its conservative collision bound and operational limitations are documented. No cryptographic primitive replacement was justified by this audit.

### Final verification

- `cargo fmt --all -- --check`: exit 0, passed (after formatting).
- `cargo test --workspace --locked`: exit 0; **54 library unit tests + 2 integration tests passed**, 0 failed, 0 ignored. CLI unit tests: 0; doc tests: 0. The library unit suite completed in 34.55 seconds in this run. All original tests remain, with 9 added v3 regression/layout tests.
- `cargo clippy --workspace --all-targets --locked -- -D warnings`: exit 0, no warnings or errors.

No commit was created. The original untracked audit report remains untracked, with this status section appended.
