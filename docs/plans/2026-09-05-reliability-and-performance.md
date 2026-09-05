# Plan: reliability and performance with backward compatibility

Date: 2026-09-05
Status: proposed implementation plan; no implementation is authorized by this
document alone.

## Objective and scope

Fix recovery and mutation correctness, make existing checkpoints dependable,
define durability, and remove straightforward performance costs. Preserve the
single writer, append-only data layout, in-memory `BTreeMap`, raw-device support,
and optional encryption.

Backward compatibility is an explicit user requirement, clarified to mean that
new code must read older data. Older binaries do not need to read new data or keep
working. Versioned format/encryption improvements are therefore in scope, while
repairs that do not need format changes can ship independently.

Segment reclamation remains deferred in
[2026-09-05-segment-compaction.md](2026-09-05-segment-compaction.md). Alternating
full-device regions are rejected. Improvements to existing repair/export tooling
do not constitute the chosen solution for same-device reclamation.

## Compatibility contract

The user clarified the storage compatibility requirement as follows:

- Existing valid v2 files remain readable, including encrypted files, streamed
  values, full checkpoints, and logs at nonzero backing offsets.
- New files may use a new versioned format by default. There is no requirement
  that old binaries can read them, or that a legacy writer remains supported.
- Keep a legacy v2 decoding path with its original field order, enum
  discriminants, integer encodings, record lengths, encryption/KDF conventions,
  and chunk layout. Isolate that decoder instead of changing the meaning of
  already-written bytes.
- Detect the format and select its decoder. Ordinary reading never rewrites or
  migrates the source. Specify how writing to an existing legacy log is handled;
  continued legacy writes are not part of the stated compatibility requirement.
- Migration or a header upgrade must have an explicit, crash-safe protocol.
  Read compatibility alone does not make an in-place conversion safe.

For source APIs and operational defaults, avoid unrelated breakage as an
engineering preference; the user's clarification does not impose interoperability
with old binaries:

- Preserve public method signatures and successful-operation semantics. Keep
  valid rename replacement behavior and the established batch ordering.
- Public configuration structs are constructed with struct literals. Adding
  required fields breaks callers. Prefer additive methods or a separate opt-in
  options entry point over changing these structs.
- Do not add required methods to `JournalStore`, restrict its existing generic
  interface, or casually add variants to public enums that downstream callers
  may exhaustively match. Check the public surface before each change.
- Preserve the current minimum supported Rust version and platform support unless
  a separate compatibility decision is made.
- Correctness fixes may reject invalid inputs and corrupt records, enforce
  documented readonly/create restrictions, and replace panics or hangs with
  errors. Describe these behavior changes explicitly in release notes.
- Do not silently change the default synchronization policy or streaming drop
  behavior. Any changed durability or commit-on-drop contract needs an additive
  opt-in API or an explicitly approved compatibility change.

The current code contains only a v2 implementation; a `V1` enum variant does not
establish v1 support. Determine the actual historically supported formats from
released code and fixtures before making a broader compatibility claim.

## Review evidence

The initial review ran `cargo test --workspace --locked`: 12 library tests and one
integration test passed. These test results do not establish power-loss safety.
Temporary external probes confirmed:

- Streaming-only inserts do not trigger full checkpoints.
- A streaming writer can mutate a readonly handle.
- Reading an empty streamed value panics in the tested debug build.
- Finalizing a streamed value at a nonzero base offset fails.
- Unencrypted payload corruption is returned without hash verification.
- Corrupting the newest checkpoint can make fallback open with existing keys
  missing, because replay position resets but sequence state does not.

Additional findings below are from source inspection. Convert them into focused
regressions while implementing; do not describe them all as experimentally
verified failures.

## 1. Establish compatibility fixtures and test boundaries

Before changing persistence behavior:

- Capture representative v2 fixtures from the pre-change revision and, where
  available, actual supported releases. Record producer revision and settings.
- Include empty and populated logs, encryption on/off, multi-chunk values,
  streaming, rename/delete/batch history, checkpoints, and nonzero offsets.
- Test new readers against those fixtures and round trips of the new format.
  Test mixed-format dispatch, wrong keys, unsupported versions, and corrupt new
  envelopes without falling back to legacy decoding. Old-reader/new-file tests
  are not a release requirement.
- Keep a small downstream compilation fixture exercising public config literals,
  builders, reader/writer APIs, and a `JournalStore` implementation.
- Add a narrow internal storage seam for injected write/seek/flush/sync failures
  where needed. Avoid redesigning the public storage abstraction for testing.

Acceptance: tests protect legacy readability and new-format round trips before
refactoring begins; a public API fixture catches unrelated source breakage.

## 2. Repair opening, replay, and bounds checking

Primary files: `journal/v2/read.rs`, `journal/v2/mod.rs`, `journal/v2/data.rs`.

- Reset sequence, position, buffering, and temporary reconstruction state when
  checkpoint restoration fails. A failed restore must not publish a partial tree.
- Remove the test-only panic that prevents tests from exercising production
  checkpoint fallback. Test failed restoration both at the committed tail and
  with subsequent committed operations.
- Reuse an older usable checkpoint or replay the intact v2 history when possible.
  Never silently return a partial namespace as successful normal recovery.
- Validate the selected superblock's supported version, tail, sequence, index
  pointer, and backing-region bounds. Finish replay at the expected boundary.
- Reject incomplete records inside committed history; distinguish uncommitted
  trailing bytes from corruption of committed data.
- Validate action lengths, chunk sizes/counts, payload lengths, pointer arithmetic,
  integer conversions, and decompressed checkpoint structure. Avoid allocation
  directly from unchecked disk lengths and arithmetic overflow/underflow.
- Preserve valid large existing logs: bounds should follow actual region/format
  limits or explicitly configurable resource limits, not arbitrary new small caps.
- Verify the existing index payload hash over the same representation used when
  writing it, before decompression and deserialization.

Do not silently roll back to an older committed state when later acknowledged
data is corrupt. Any salvage with possible data loss belongs in explicit repair
and must report what could not be recovered.

Acceptance: damaged checkpoints either recover the complete committed namespace
from intact history or return an error; malformed records do not panic, hang,
overflow, or trigger unbounded decoding. Existing valid fixtures remain readable.

## 3. Unify mutation ordering and writer ownership

Primary files: `lib.rs`, `state.rs`, `journal/v2/mod.rs`, `journal/v2/write.rs`.

- Acquire the common mutation lock for batches as well as other mutations.
  Document lock ordering; never hold the tree lock while waiting for a streaming
  writer that requires the tree lock to finish.
- Validate operations before writing; publish memory-index changes only after
  the journal operation reaches its defined successful boundary. In particular,
  move `remove()`'s memory deletion after journal success.
- Preserve current batch order: deletes first, followed by renames in list order.
  Validate against that evolving state using an overlay for touched keys rather
  than cloning a potentially million-key tree. Handle duplicate sources,
  delete/rename conflicts, rename chains, and destination replacement explicitly.
- Share the relevant state-transition logic between live application, replay,
  and repair so the same persisted batch has the same result everywhere.
- Use an ownership guard or equivalent explicit lifecycle for the borrowed
  writer. Every error must return a usable writer or close/taint it and wake all
  waiters. Never leave `Available(None)` indefinitely after losing its owner.
- Preserve commit-on-drop compatibility for existing successful streaming use.
  Require internal/CLI code to call `finish()` explicitly. Add an explicit abort
  or safer writer API separately if useful; do not silently change old `Drop`
  into abort. Failure handling must avoid a second panic during unwinding.
- Define failures after partial I/O as potentially indeterminate, rather than
  implying the operation was rolled back. Block further writes if state is unsafe.

Acceptance: concurrent batch/streaming regressions terminate, injected errors do
not strand waiters, invalid batches are rejected before persistence, and memory
state matches reopening after successful operations.

## 4. Fix streaming, configuration, and device access

Primary files: `lib.rs`, `journal/v2/write.rs`, `journal/v2/read.rs`,
`journal/v2/mod.rs`.

- Enforce readonly before any streaming writer is acquired. Open readonly handles
  without write access or creation, and retain that behavior through all APIs.
- Honor `allow_create` consistently; use atomic fresh-file creation where needed.
  Treat formatting an existing raw device as distinct from ordinary opening.
- Define zero-length values consistently across insert, streaming, whole reads,
  readers, and chunk iteration, using the established valid v2 representation.
  Handle zero chunk size, exact chunk multiples, maximum chunk IDs, zero-length
  read buffers, and skips at/beyond EOF without panics or nonce collisions.
- Separate absolute backing offsets from log-relative offsets internally. Fix
  streaming finalization and checkpoint seeks at nonzero base offsets.
- Define raw-mode semantics and optionally bounded backing regions through an
  additive API. Validate capacity before writes where sizes are known; streaming
  writes must enforce bounds incrementally. Preserve bytes outside the region.
- Exclude independent writers for the lifetime of an open writable store. Select
  a locking implementation compatible with the current MSRV and platforms.
  Specify readonly coexistence; separate readonly opens are not automatically a
  live-updating view. Locks only protect against cooperating access.

Acceptance: encrypted/plain and regular/streaming combinations cover lengths 0,
1, chunk-1, chunk, chunk+1, and multiple chunks, including nonzero offsets and
fixed-capacity backing. Readonly operations leave backing bytes unchanged.

## 5. Complete the existing checkpoint mechanism

Primary files: `lib.rs`, `state.rs`, `journal/v2/mod.rs`, `journal/v2/write.rs`.

- Run checkpoint scheduling after every successful mutation path, including
  streaming completion, through one common path.
- Expose an additive explicit `checkpoint()` operation. Support bulk operations
  using existing interval configuration and a final explicit checkpoint.
- Define the interval unit and boundary precisely, and reconstruct progress since
  the last checkpoint on reopening. Avoid the current mix of per-key counters
  and per-entry documentation. Define behavior for an interval of zero.
- Distinguish a committed user mutation from failure of its subsequent automatic
  checkpoint. Do not introduce ambiguous retries by reporting that a committed
  mutation simply failed. Specify how checkpoint errors and a tainted journal
  are surfaced without breaking existing result types.
- Measure checkpoint serialization/compression time, snapshot bytes, replayed
  entry count, and checkpoint-load versus tail-replay time.
- Benchmark lower Brotli quality and the already-supported uncompressed snapshot
  representation. Avoid selecting fixed thresholds before measurements.
- Reduce intermediate allocations. Keep v2 snapshot decoding intact; introduce
  changed snapshot encodings only under an explicit format version. Keep snapshot
  consistency explicit; do not move serialization outside locks without a stable
  view and bounded memory cost.

Full checkpoints remain the default design. The current partial-checkpoint shape
cannot represent deletions correctly by merely enabling its parent pointer;
document/deprecate the inactive option compatibly rather than activating it.
Chunk-framed checkpoints that change the encoding belong to the versioned format
work and need not also be understood by old readers.

Acceptance: streaming-only workloads checkpoint and reopen correctly, explicit
checkpoints work after bulk writes, and both legacy and new snapshots are readable
by the new code. Checkpoint failures have documented mutation-outcome semantics.

## 6. Remove simple performance costs and correct accounting

Primary files: `journal/v2/write.rs`, `journal/v2/read.rs`, `journal/v2/mod.rs`,
`state.rs`.

- Replace repeated `Vec::split_off()` of the remaining value tail with slice
  iteration and reusable chunk storage. Keep this optimization separate from
  changes to record/encryption framing; copying should scale linearly with value
  size. Preserve legacy decoding even when the new writer changes its framing.
- Reuse read buffers and avoid allocating/copying every intermediate chunk when
  filling the final result. Preserve authentication before exposing encrypted
  chunk contents and correct partial-read behavior.
- Tie reads to the opened backing object rather than reopening its pathname for
  each request. Prefer positional reads or another simple implementation with
  independent logical cursors. Cloned descriptors with independent seeks are not
  sufficient because the underlying cursor can be shared.
- Keep the `BTreeMap`; correct its misleading prefix-sharing comment. Add cursor
  pagination only if deep offset pagination is a demonstrated use case.
- Count obsolete values on overwrite and rename destination replacement, without
  counting a same-name rename as obsolete data. Preserve `None` for unknown
  obsolete-byte totals after checkpoint restoration.
- Keep logical payload size, occupied log bytes, and backing-device capacity
  distinct. Add clarified metrics rather than silently changing existing public
  size-method semantics, including their base-offset behavior.

Acceptance: representative small-value, large-value, and many-key benchmarks show
where costs changed. Accounting is consistent across mutation/replay where an
estimate is available; no speculative index replacement or payload compression
feature is included.

## 7. Add explicit durability without changing default compatibility

Primary files: `journal/v2/write.rs`, `journal/v2/mod.rs`, `lib.rs`.

Current `flush()` calls drain Rust buffering but do not establish power-loss
durability. Document this accurately. Introduce opt-in durability configuration
through an additive API and/or an explicit `sync()` operation; preserve the
legacy default unless the user explicitly approves changing it.

Specify separately: accepted writes, visibility to in-process readers, and
acknowledged durable commits. For durable commits, use an ordered protocol:

1. Finish records and flush buffering.
2. Synchronize data before publishing a superblock that references it.
3. Write the next superblock and synchronize it.
4. Only then acknowledge the durable boundary.

Group synchronization can amortize costs, but needs an explicit boundary. Do not
assume that one final sync retroactively protects the old root during earlier
unsynchronized superblock rotations. Design the opt-in mode's root-publication
policy from the outset. Include file creation/directory durability where relevant
and platform-specific raw-device behavior in the documented storage model.

Use a narrow fault-injection model to test persistence ordering, partial writes,
and failed syncs, not only process termination (which leaves OS caches alive).
Document indeterminate outcomes when synchronization reports failure.

The v2 layout puts ten 256-byte roots into 2,560 bytes and lacks plain root
checksums. Ordered syncs improve it but do not establish independent root failure
units or complete corruption protection. Do not claim those format limitations
are fixed by compatible changes alone.

Acceptance: the opt-in durability contract is demonstrated under its stated fault
model, legacy APIs retain their defaults, and limitations of v2 remain explicit.

## 8. Repair, integrity verification, and existing copy tooling

Primary files: `journal/v2/repair.rs`, `journal/v2/mod.rs`,
`journal/v2/read.rs`, `logfs_cli/src/main.rs`.

- Honor repair `dry_run`, open the source readonly, and reject output aliases,
  existing destinations, and overlapping regions. Never overwrite the only source
  as an implicit repair step.
- Replace the unencrypted recovery scanner's `todo!()`. Check candidate headers,
  sequences, offsets, payload bounds, and available hashes conservatively; keep
  overlaps between scan buffers and handle short final buffers. Seeking past EOF
  is not evidence that a payload exists.
- Apply batch actions in the same order as normal replay, handle missing names
  without panics, and report skipped/corrupt/unrecoverable contents explicitly.
- Stream output values with explicit finish, write a final full checkpoint,
  synchronize using the chosen durability policy, and reopen/verify the result.
- Repair the existing copy/compact command's source consistency, destination
  freshness, final checkpoint, error propagation, and verification. Treat this
  as export/migration tooling, not the deferred same-device reclamation solution.
- Add an explicit scrub/verify operation that checks stored value hashes and
  encrypted authentication. Verify full-read hashes where metadata is available.
  Existing v2 checkpoints omit value hashes and entry-header locations, so define
  a compatible metadata-recovery path rather than pretending that adding a runtime
  hash field alone fixes checkpoint-restored reads.
- Document streaming verification limits: a whole-value hash is known only after
  EOF, and a partial read cannot claim whole-value verification. Do not imply that
  v2 plaintext chunks contain independent checksums.

Acceptance: dry runs do not write, repaired/exported contents match reported
recoverable state, and deliberate corruption is detected at the promised scope.
Copying encrypted data must not be advertised as fixing the v2 nonce design.

## 9. Versioned encryption with a legacy superblock fallback

Use a new superblock encoding for new logs and retain legacy decryption for old
logs. This satisfies the clarified read-compatibility requirement without
retaining the unsafe legacy encryption scheme for new writes. A new format does
not require segment allocation, an on-disk tree, or a wholesale storage rewrite.

The current writer encrypts superblocks using `(sequence = 0, slot index)` and
reuses those nonces on updates. Keep that exact convention only in the legacy
decoding path. The new scheme needs an explicitly versioned envelope containing
enough information to derive/select its key domain and nonce before decryption.
Bind the version, identity, generation, and relevant envelope fields to the
authenticated contents. Define a nonce allocation or key-domain protocol that
remains safe after failed writes and crashes; a generation recovered from an old
root can roll back, and random 96-bit nonces require an explicit collision budget.
A fresh per-file salt alone does not solve within-file nonce reuse.

Format dispatch and fallback requirements:

1. Probe the documented root locations without modifying the backing object.
2. Recognize a new-format envelope and decode it with the new scheme.
3. Select legacy decoding only when format identification establishes a legacy
   log. Do not catch a new-format authentication failure and blindly retry the
   legacy scheme. A wrong key, unsupported version, or damaged new root is not
   permission to downgrade.
4. Validate redundant candidates and their common log identity before choosing a
   generation. Design detection to handle torn markers and reject ambiguous or
   conflicting layouts; do not depend on one fragile marker with no redundancy.
5. Once the format is established, use its checkpoint and entry decoders. Reuse
   existing entry structures where safe instead of gratuitously changing them.

Superblock fallback solves readability, not every nonce issue. Also specify:

- Stream finalization that does not re-encrypt changed metadata under the same
  nonce. Prefer writing finalized metadata once or an immutable authenticated
  completion record, with a bounded recovery protocol.
- Entry/chunk key-domain uniqueness across abandoned writes, reopen, copies, and
  retries. Advancing only the committed sequence does not address abandoned
  ciphertext written beyond the committed tail.
- A small number of independently aligned roots with generations, magic/version,
  region bounds, and checksums/authentication. Alignment is not an assumption of
  atomic writes; include append-tail failure behavior in the fault model.
- Metadata integrity, value integrity accessible after checkpoint restoration,
  and checkpoints that can be processed with bounded working memory.

New-file creation should use the corrected version once implemented and verified.
Legacy files remain readable. Decide whether writable legacy opens return a
migration-required result or retain an explicitly documented legacy write mode;
do not imply that legacy writes have acquired the new encryption guarantees.

An existing v2 header occupies only 2,560 bytes followed immediately by entries.
A larger root layout cannot overwrite those entries. Evaluate a header-only
upgrade only if its layout, decoder dispatch, and interruption protocol are
demonstrably safe. Otherwise use explicit verified migration. Converting entry
encryption may require rewriting values even if a root-only upgrade is possible.
Same-device migration without spare capacity remains an open problem; neither a
legacy decoder nor the deferred compaction plan automatically solves it.

Acceptance: all supported legacy fixtures remain readable, new writes use the
corrected crypto protocol, corrupt/wrong-key new logs cannot downgrade to legacy
decoding, and interruption tests cover nonce/domain allocation and any upgrade.

## Delivery order and completion criteria

Suggested reviewable changes:

1. Compatibility fixtures and focused recovery regressions.
2. Replay reset, bounds validation, and checkpoint hash verification.
3. Mutation ordering, batch validation, and writer error lifecycle.
4. Streaming/configuration/offset fixes and backing-object access protection.
5. Common checkpoint scheduling and explicit checkpoints.
6. Linear chunk writing, buffer improvements, and correct space accounting.
7. Versioned superblock/entry encryption with legacy readers, developed together
   with durable root publication and persistence-failure tests.
8. Repair/scrub/export hardening, verified migration, and documentation.

Segment compaction stays deferred. Format changes are allowed by the clarified
compatibility requirement, but their exact encoding and migration protocol still
need design and validation. Early releases containing only v2 repairs must not be
labeled as having solved all encryption or power-loss limitations.

For each change, run relevant regression tests plus the compatibility suite. Run
workspace tests, formatting, and the project's required lint/MSRV/platform checks
before release. Use isolated temporary files and bounded failure tests; compare
logical behavior against a reference map for overlapping mutation sequences.

Performance measurements should separate checkpoint loading, tail replay,
compression, allocation/copying, and durable-write costs. Do not compare buffered
and synchronized writes as if they offered the same guarantee.

Open decisions before their dependent work: historically supported release range;
precise durability/error contract; target region and locking semantics; workload
scale and checkpoint budget; exact versioned crypto/record layout; and handling
of writable legacy opens and same-device migration. Read compatibility with older
formats is required; old binaries reading new formats is explicitly not required.
