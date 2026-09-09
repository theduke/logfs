# LogFS v3 byte format

Status: documents the implementation as of 2026-09-09, including the v3 audit fixes. The refactor preserves existing v3 bytes and cryptographic domains. This document describes both the writer's canonical encoding and the reader's actual acceptance rules; permissive decoding is not an extension mechanism.

Implementation map: `logfs/src/journal/v3/format.rs` (frames), `root.rs` (root envelopes and bootstrap), `index.rs` (snapshots), `limits.rs` (resource budgets), `read.rs`, `write.rs`, and `repair.rs`. Shared wire types are in `journal/data.rs`; bounded bincode decoding is in `journal/codec.rs`. Legacy root/entry decoding and checkpoint schemas/policy are in `journal/v2`. The historical public name `Journal2` is retained for API compatibility; new journals use v3.

## Coordinates and backing regions

Let `B` be the configured absolute backing-file byte offset of the log region. Let `R` be its optional configured capacity, and `T` its committed, region-relative tail. Intervals below are half-open. All additions, multiplications, and conversions must be checked for overflow before seeking or allocating.

| Object | Stored coordinate / physical interval |
| --- | --- |
| Root slot 0 | `[B, B + 4096)` |
| Root slot 1 | `[B + 4096, B + 8192)` |
| First frame | Starts at `B + 8192` |
| Root `tail_offset` | Relative `T`; first uncommitted byte is `B + T` |
| Entry header `offset` | Relative; points at that frame's 24-byte seed |
| `EntryPointer.offset` | Relative; also points at the seed |
| Snapshot key `file_offset` | **Absolute backing-file offset** of the first value chunk |
| Repair `skip_bytes` | Absolute offset at which byte scanning begins; defaults to zero |

For bounded regions, `8192 <= T <= R`. Root slots and committed frames must fit in the region. Normal opening rejects a committed tail beyond physical EOF or beyond a caller-supplied region capacity. EOF can exceed `B + T` because of abandoned writes, preallocation, another region, or trailing backing-file data. Those bytes are not part of normal replay.

The region base and capacity are supplied out of band; neither is a root field. A region image is not generally relocatable by byte-copy: snapshot key offsets are absolute. Export/rewrite/migration produces fresh offsets, identities, keys, and nonces. Even where a log without a checkpoint happens to replay after relocation, arbitrary relocation is not a compatibility promise. The repair API does not accept `R`; it scans up to backing EOF using the configured base and authenticated/checksummed framing. Callers needing a physically restricted salvage range must supply an appropriately restricted source.

## Primitive encoding and fixed identifiers

All multibyte integers use **little endian, fixed width**, without alignment gaps. Serialization is bincode **1.3.3** with Serde, matching `bincode::serialize` and `bincode::deserialize`: little endian, fixed integers, trailing bytes allowed. Bounded decoding explicitly uses `DefaultOptions::new().with_fixint_encoding().allow_trailing_bytes().with_limit(limit)`; using `DefaultOptions` without these settings would change the format.

| Rust/wire concept | Encoding |
| --- | --- |
| `u8`, `u32`, `u64` | 1, 4, 8 bytes respectively |
| SequenceId / NonZeroU64 | 8-byte u64, zero invalid |
| Enum variant | 4-byte **zero-based declaration ordinal**, then variant fields |
| `Option<T>` | One byte: `00` for None, `01` followed by T for Some; other tags invalid |
| String | u64 UTF-8 byte length, followed by those bytes; valid UTF-8 required |
| Vec | u64 element count, then consecutive element encodings |
| Fixed byte array | Exactly its array length, without a length prefix |
| Struct / newtype | Fields in declaration order; no names, padding, or struct envelope |
| Bitflags | Underlying u32 bits |

The following values are frozen. Rust `repr` values do **not** override Serde enum ordinals.

| Enum | Discriminants |
| --- | --- |
| `LogFormatVersion` | V1 = 0; V2 = 1; **V3 = 2** (despite Rust's `V3 = 3`) |
| `CryptoProfile` | Standard = 0; LowMemory = 1 |
| `CompressionFormat` | Brotli = 0 |
| `JournalAction` | KeyInsert = 0; KeyRename = 1; KeyDelete = 2; IndexWrite = 3; Batch = 4; IndexWriteV3 = 5 |

The root payload's separate `version: u32` is the literal number **3**, not an enum. Shared `Superblock::SERIALIZED_LEN`, `HEADER_COUNT`, and `HEADER_SIZE` are historical v2 constants (256, 10, 2560); they must never be used for v3 framing.

## Root slots and envelopes

Each root slot is exactly 4096 bytes. There is no cleartext v3 magic marker or cleartext KDF/profile selector. Encryption mode, password, and profile are supplied out of band. Two independently generated 16-byte salts are fixed for the lifetime of the log; every root contains both salts internally. The plaintext mode also writes random salts, a random log secret, and random nonce fields, but does not use them as secret encryption keys.

| Slot-relative offset | Length | Field |
| --- | --- | --- |
| 0 | 16 | This slot's salt |
| 16 | 24 | Fresh outer XChaCha nonce (also random in plaintext mode) |
| 40 | 4056 | Encrypted mode: ciphertext of the 4040-byte outer cleartext followed by its 16-byte tag |
| 40 | 4024 | Plaintext mode: cleartext containing length + payload + random padding |
| 4064 | 32 | Plaintext mode only: SHA-256 of slot bytes `[0, 4064)` |

### Encrypted outer cleartext (4040 bytes)

Offsets in this table are relative to the decrypted outer body, not the slot.

| Offset | Length | Field |
| --- | --- | --- |
| 0 | 32 | Bootstrap log secret |
| 32 | 24 | Fresh inner root nonce |
| 56 | 4 | Inner ciphertext length `L`, including its tag |
| 60 | L | Encrypted serialized `V3RootPayload`, with a 16-byte tag |
| 60 + L | 3980 - L | Padding, zero-filled by the current encrypted writer |

`L` must be nonzero and fit in the remaining outer cleartext. The inner payload is authenticated with the root-purpose key derived from the log secret. Its embedded secret must equal the bootstrap secret. Both encryption layers bind the **physical slot index** as the single AAD byte `00` or `01`.

### Plaintext root body (4024 bytes)

At body offset 0 is a u32 payload length `P`, then `P` serialized payload bytes starting at offset 4, followed by random padding. `0 < P <= 4020`. The slot checksum covers salt, nonce, length, payload, and padding. It detects accidental damage; anyone able to edit plaintext bytes can recompute it.

### Serialized root payload

Let `q = 0` when `last_index_entry` is None, and `q = 16` when it is Some. Canonical payload length is `202 + q`; canonical inner ciphertext length is `218 + q`.

| Payload offset | Length | Field |
| --- | --- | --- |
| 0 | 16 | Magic: ASCII `LOGFS-OPAQUE-V3` followed by one zero byte |
| 16 | 4 | Version u32 = 3 |
| 20 | 4 | CryptoProfile ordinal |
| 24 | 16 | Random, nonzero log identity |
| 40 | 1 | Physical slot index |
| 41 | 8 | Root generation |
| 49 | 4 | Superblock format ordinal = 2 |
| 53 | 4 | Superblock flags = 0 |
| 57 | 8 | Active sequence; zero for an empty log |
| 65 | 8 | Relative committed tail `T` |
| 73 | 1 + q | Optional latest index pointer: tag, then sequence u64 and relative offset u64 |
| 74 + q | 32 | Log secret |
| 106 + q | 32 | Root salts: slot 0's 16 bytes, then slot 1's 16 bytes |
| 138 + q | 32 | Committed history value |
| 170 + q | 32 | History immediately **before** the latest checkpoint entry |

The magic's precise 16 bytes are `4c 4f 47 46 53 2d 4f 50 41 51 55 45 2d 56 33 00`.

Normal opening authenticates/checksums both slots, validates each payload, requires the slot to equal `generation mod 2`, and requires identical identity, secret, and salt pair with generations differing by exactly one. For encrypted roots the stored profile must match the supplied profile. Each root's tail and checkpoint pointer must be structurally valid; nonzero superblock flags and active sequence `u64::MAX` are rejected. A checkpoint pointer must lie in `[8192, T)`, with sequence in `[1, active_sequence]`. The newest valid generation is selected only after both roots pass. Root generations may change without a new user mutation (e.g. initialization/checkpoints).

Creation writes generation 1 to slot 1 and generation 2 to slot 0, both with sequence 0, tail 8192, no checkpoint, and zero history values. Each publication increments the generation and alternates the slot. Generations never wrap; exhaustion is an error.

## Encryption, derivation, and key separation

Encrypted v3 uses XChaCha20-Poly1305: 32-byte keys, 24-byte nonces, and 16-byte appended authentication tags. Plaintext metadata uses SHA-256 instead of AEAD; plaintext value chunks have no per-chunk checksum.

For each physical root slot `s`, derive a 32-byte password key using Argon2id version 0x13 (Argon2 v1.3), UTF-8 password bytes, and that slot's stored salt. Named profiles are fixed:

| Profile | Memory | Passes | Parallelism | Output |
| --- | --- | --- | --- | --- |
| Standard | 65536 KiB | 3 | 1 | 32 bytes |
| LowMemory | 8192 KiB | 3 | 1 | 32 bytes |

Root password key separation uses HKDF-SHA256 with extract salt ASCII `logfs/v3/root`, input key material equal to the Argon2 output, and expand info equal to the single slot byte. Expand produces the outer root's 32-byte AEAD key.

The random 32-byte per-log secret feeds HKDF-SHA256 with extract salt ASCII `logfs/v3/log-secret`. Four separate 32-byte expansions use these exact ASCII info strings:

| Info | Purpose |
| --- | --- |
| `root` | Inner root payload encryption |
| `entry` | Entry headers, actions, and ordinary value chunks |
| `checkpoint` | Checkpoint payload chunks |
| `history` | HMAC-SHA256 history commitments |

Legacy PBKDF2 configuration salt/iterations do not select v3 KDF parameters. Profile IDs must never be reinterpreted; a future parameter set needs a new negotiated format/profile contract. Passwords, derived key material, retained secrets, root cleartext buffers, and bootstrap secrets use zeroizing storage where feasible. This is memory hygiene, not a guarantee that the compiler/runtime never makes transient copies.

## Entry framing and authentication

Every frame starts with a fresh random 24-byte seed `N`. It is followed by a fixed-size authenticated/checksummed header, a variable-size authenticated/checksummed action, and an action-dependent payload. Let `M = 16` for encrypted metadata or `32` for plaintext metadata; let `A` be serialized plaintext action length; let `D` be encoded payload length.

| Frame-relative offset | Length | Field |
| --- | --- | --- |
| 0 | 24 | Entry seed N |
| 24 | 256 + M | Encoded header including tag/checksum |
| 280 + M | A + M | Encoded action; length is stored in the header |
| 280 + 2M + A | D | Value/checkpoint payload, if any |

Formulas:

```text
searchable_header = 24 + 256 + M               = 296 encrypted / 312 plaintext
action_size       = A + M                     (u32)
frame_size        = 24 + 256 + 2M + A + D
absolute_payload  = B + header.offset + searchable_header + action_size
next_frame        = absolute_payload + D
scanner_overlap   = searchable_header - 1     = 295 encrypted / 311 plaintext
```

### Header plaintext (256 bytes)

| Offset | Length | Field |
| --- | --- | --- |
| 0 | 4 | Serialized frame-header length; canonical value 88 |
| 4 | 8 | Region-relative frame offset |
| 12 | 8 | Nonzero entry sequence |
| 20 | 4 | Encoded action length `A + M` |
| 24 | 4 | Entry flags; bit 0 is INCOMPLETE |
| 28 | 32 | Previous history value |
| 60 | 32 | This entry's history value |
| 92 | 164 | Padding; zero in encrypted mode, random in plaintext mode |

The parser requires a nonzero declared length at most 252 and a decodable header within it. Normal replay and salvage reject INCOMPLETE. Canonical committed flags are zero. Current readers retain unknown entry flag bits and ignore them; see evolution rules below. The fixed 256-byte clear header, including padding and its length field, is authenticated/checksummed as one unit.

### Chunk identifiers, nonces, and associated data

Chunk identifier 0 is the header, 1 is the action, and value/checkpoint chunks begin at 2. Identifiers are u32. For each chunk `c`:

```text
nonce(N, c) = N[0..20] || LE32(LE32_decode(N[20..24]) XOR c)
AAD         = log_identity[16] || original_N[24] || LE32(c)   (44 bytes)
```

The original seed in AAD is never replaced by the derived nonce. Header/action/value encryption uses the entry key, while checkpoint payload encryption uses the checkpoint key. Plaintext metadata appends `SHA256(AAD || clear_bytes)`. No hash/tag is prepended. Frame seeds are generated again for each new entry attempt; uncommitted sequence numbers may be reused after abort/reopen with a new seed.

For a fixed seed the XOR mapping is injective. Across entries the nonce schedule is probabilistic: matching 160-bit seed prefixes is a conservative upper bound on possible overlapping chunk nonce sets; for `n` independent seeds the prefix-collision union bound is `n(n-1)/2^161`. An actual repeated nonce also requires suffix/chunk combinations to coincide under the same key. There is no persistent seed collision registry or built-in rotation threshold. New logs/export destinations receive new secrets, identities, and independent root salts. Do not clone live writer state into independent writers or promise unbounded writes under one key.

## Actions and values

Fields in the following table follow the u32 action discriminant, in the exact listed order. Nested structs add no bytes beyond their fields.

| Action | Payload fields inside the serialized action |
| --- | --- |
| KeyInsert (0) | size u64; chunk_size Option<u32>; whole-value SHA-256 `[u8;32]`; path String |
| KeyRename (1) | Vec of `(old_key String, new_key String)` |
| KeyDelete (2) | Vec of String paths |
| IndexWrite (3), legacy snapshot schema | size u64; snapshot hash `[u8;32]`; compression Option<CompressionFormat> |
| Batch (4) | Vec of `(old_key String, new_key String)`; then Vec of deleted String paths |
| IndexWriteV3 (5) | size u64; snapshot hash `[u8;32]`; compression Option<CompressionFormat> |

An insert action is `53 + UTF8(path).len()` bytes with chunk_size None, or `57 + UTF8(path).len()` with Some. Index actions are 45 bytes without compression, 49 with Brotli. No-value rename/delete/batch actions have `D = 0`. Batch replay performs deletes first, then renames, despite the wire field order. Insert replaces the existing value at its path. Missing sources during replayed renames and missing deleted keys are tolerated by the current state application.

For an insert, let `S` be plaintext value length. If chunk_size is None there is one chunk; otherwise for positive chunk size `C`, the count is `k = max(1, ceil(S/C))`. The last chunk contains the remaining bytes; all earlier chunks have exactly C bytes. Chunk identifiers are consecutive, beginning at 2. Empty v3 values have one empty chunk (and one tag in encrypted mode), unlike historical v2 empty values. No per-chunk length word is written.

```text
value_encoded_length = S + k * E     where E = 16 encrypted, 0 plaintext
```

The insert hash is SHA-256 of concatenated plaintext value bytes. Routine reads may skip whole-value hash verification according to `ReadIntegrity`; encrypted chunk authentication is mandatory in either setting. Scrub, export, and recovery copying request whole-value verification. Reads through an externally supplied pointer must still enforce size/chunk arithmetic and available backing-file bounds.

## Checkpoints and indexes

Canonical v3 writers emit IndexWriteV3 and an **uncompressed full snapshot**. The action size field is the serialized snapshot length before encryption. Its SHA-256 is over those payload bytes (compressed bytes if a reader encounters the supported Brotli form), before encryption. The payload is one chunk at identifier 2 using the checkpoint key, with `D = size + E`.

The snapshot is one Vec of entries; its initial u64 is the number of keys. Writers emit BTreeMap key order. Entries contain:

| Order | Field | Width |
| --- | --- | --- |
| 1 | Key UTF-8 String | 8 + key byte length |
| 2 | Original insert sequence | 8 |
| 3 | Original entry seed, Option<[u8;24]> | 1 or 25; Some required by v3 restoration |
| 4 | Absolute file offset of value data | 8 |
| 5 | Plaintext value size | 8 |
| 6 | Chunk size, Option<u32> | 1 or 5 |
| 7 | Whole-value hash, Option<[u8;32]> | 1 or 33 |

Writers retain the insert hash and seed. The hash remains optional on the wire; current restoration permits None and cannot invent a missing whole-value hash. Snapshot entries omit the log identity because it comes from the authenticated root. V3 snapshots contain no parent pointer.

Restoration checks the snapshot hash, bounded decoding/decompression, unique keys, positive chunk sizes when present, sequence older than the checkpoint, chunk-count arithmetic, and value pointer range. Value starts must precede the checkpoint and be at or beyond `B + 8192`; occupied bytes must not extend beyond the committed tail. These are the current checks; restoration does not independently reread every referenced insert header or require every value's end to precede the checkpoint. Subsequent verified reads authenticate the stored seed/identity/chunks and check the retained whole-value hash.

The root stores the latest checkpoint pointer and the history immediately before that entry. Random v3 checkpoint seeks require that exact authenticated pointer. After restoring the checkpoint, replay continues through later entries to the committed boundary. On checkpoint restoration failure, the reader discards restored state, resets sequence/history to the first entry, and attempts full replay. Reopen succeeding therefore does not by itself prove checkpoint restoration succeeded.

The legacy IndexWrite (3) schema remains readable for compatibility: its snapshot is `parent_entry Option<EntryPointer>` followed by a Vec of `(key String, sequence u64, absolute file_offset u64, size u64, chunk_size Option<u32>)`. It lacks seed and hash fields. Parent pointers must move strictly backward in both offset and sequence; repeated pointers and duplicate keys within a snapshot are rejected. Newer snapshot entries win when traversing parents. This is legacy compatibility, not the v3 writer's canonical snapshot.

## History and committed state

Before the first entry the history is 32 zero bytes. For each frame, with `P` its predecessor and `action_plain` the exact serialized action bytes:

```text
encrypted H = HMAC-SHA256(history_key, P || identity || N || action_plain)
plaintext H = SHA256("logfs/v3/plain-history" || P || identity || N || action_plain)
```

The clear header stores P and H. Normal replay requires P to equal its expected predecessor, recomputes H, validates the expected sequence and physical region-relative offset, and rejects incomplete or out-of-bound frames. Payload bytes are committed indirectly through insert/snapshot hashes in the action. The selected root authenticates the final H, active sequence, and committed tail. Replay must reach all three consistently; reaching the tail with the wrong sequence/history fails. At a checkpoint the expected predecessor is supplied by the root's checkpoint-history field.

This binds file identity and history branches and detects encrypted frame substitution under the reviewed checks. It does not detect restoration of an entire older valid file image without external trusted state. Plaintext checksums and plaintext history are not adversarial authentication.

## Publication, streaming, and crashes

Only one writer owns a log at a time; writable opens use an exclusive file lock, and readonly/recovery sources use shared locks. Locking is an implementation coordination mechanism, not a byte-format field.

For buffered operation, entry bytes are written/flushed before root publication, and root writes are flushed. Durable operation additionally orders: write entries → flush entry data → `sync_data` → overwrite the next root slot → flush root → `sync_all`. The selected root is the published commit boundary. A partial/unpublished frame is ignored by normal open. Writes do not assume a 4096-byte root overwrite is atomic; a torn root can make strict open fail and require explicit salvage.

Streaming reserves random metadata bytes sized for the final action/header, writes chunks under one fresh seed, and only at finalization fills in the completed hash/size and authenticated metadata. It then publishes the root. The reserved random metadata is not an authenticated provisional frame, avoiding repeated metadata encryption under the same seed. Abort rewinds the writer to the frame start without publishing the reservation; abandoned bytes may remain beyond the committed tail. I/O or finalization failures taint the writer until reopen. Predictable action-size/capacity rejection before reservation or ordinary entry emission leaves it usable. An unknown-length stream can still exhaust capacity after writing has begun.

Automatic checkpoint failure after a successful mutation does not undo that committed mutation. The next open can use an earlier checkpoint and replay. Region randomization, when requested at creation, fills unused capacity with random bytes; ordinary growth/committed-length hiding is not otherwise guaranteed.

## Explicit recovery

Normal open retains strict pair validation. Explicit repair has a separate bootstrap: it tries each v3 root independently, verifies its authentication/checksum and internal identity/slot/profile/bounds, and can use one surviving root. It allows the authenticated tail to exceed physical EOF so intact earlier entries remain salvageable. If both roots authenticate but disagree on identity, secret, salt pair, or adjacent generations, repair refuses the ambiguous pair. It never substitutes an unauthenticated encrypted root or a caller-supplied guessed secret. With neither root usable, this API cannot recover encrypted v3 records.

Repair emits a warning that the latest committed state is uncertain. It scans windows of at most 100000 bytes for the requested sequence, overlapping by the complete header length minus one. Candidate headers must authenticate/checksum, have the requested sequence, have the correct relative offset, and not be incomplete. Failed candidates do not allocate per-byte diagnostic backtraces. After a match, recovery reads consecutive entries until malformed metadata, authentication failure, sequence/offset mismatch, an incomplete entry, or a payload extending beyond EOF stops it.

Salvage is not strict replay: it may start at a later requested sequence, does not anchor the recovered chain to the root's committed history/tail, and may recover complete unpublished entries. The current salvage reader authenticates/checksums individual headers/actions but does not enforce their history predecessor/commit fields as a chain. It skips checkpoint contents while reconstructing state from mutations. It may miss earlier keys when starting later; no claim of a latest or complete committed snapshot is made.

On export, each recovered value is read with whole-value verification and encrypted chunk authentication, copied through a streaming writer into an exclusively created fresh zero-offset destination, and checkpointed/synchronized. The output is reopened and scrubbed to verify every copied value and the key count. The source is not modified. Existing output paths are not overwritten. Dry-run performs metadata scanning only and creates no destination; it is not a whole-value scrub. A failed export may leave a partial fresh destination for the caller to inspect; there is no source rewrite or automatic deletion.

## Bounds: format versus implementation

| Constraint | Format or current implementation |
| --- | --- |
| Root slot/header area | Format: 4096 bytes per slot, 2 slots, 8192 total |
| Frame clear header / seed | Format: 256 / 24 bytes |
| Encoded action length | Format: u32; includes metadata tag/checksum |
| Value/snapshot size, offsets, sequences, generation | Format fields: u64; sequence is nonzero; checked arithmetic and commit rules further restrict use |
| Chunk size / chunk identifier | Format fields: u32; data starts at 2, so representable data count is at most `2^32 - 2` |
| Writer chunk-count endpoint | Implementation: streaming increments its next-chunk cursor before accepting a chunk and therefore cannot use the last representable identifier; practical sizes are far below this endpoint |
| Action plaintext/decoded serialized-byte budget | Implementation: 512 MiB = 536870912 bytes |
| Action encoded budget | Implementation: plaintext budget + 16 encrypted / +32 plaintext, additionally fitting u32 |
| Checkpoint payload plaintext budget | Implementation: 512 MiB; encryption tag is additional |
| Checkpoint encoded budget | Implementation: plaintext budget +16 encrypted / +0 plaintext |
| Checkpoint decoded byte budget | Implementation: minimum of 512 MiB and committed region length; enforced during Brotli expansion and bounded deserialization |
| Value size/allocation | No 512 MiB metadata cap on values; physical region, u64/chunk arithmetic, usize/address space, and available memory apply. Whole-value reads allocate the whole value; streaming avoids that allocation |

Writers measure actions/snapshots before serialization, enforce the shared plaintext budget, and include encoded overhead in capacity preflight. The snapshot encoder traverses borrowed keys rather than allocating a cloned key collection. Readers validate encoded lengths before read-buffer allocation and apply decoded limits after authentication/decompression. Test-only thread-local limits exercise these same paths with small fixtures; production limits are not configurable through that mechanism.

Byte limits are not total-memory budgets: serialized buffers, decrypted buffers, strings, tree nodes, and temporary copies can coexist. No aggregate allocator budget or parser fuzzing guarantee is implied. Legacy-v2 budgets retain their prior behavior independently of v3's corrected overhead accounting.

## Compatibility and evolution rules

1. Preserve field order, widths, endianness, enum ordinals, option/vector encoding, hash inputs, KDF parameters, key labels, and nonce/AAD rules for v3. Golden byte-layout assertions in `v3/tests.rs` pin root payloads, frame headers, action forms, and discriminants. Do not change bytes by replacing Serde-derived representations without byte-for-byte fixtures.
2. Root payload version must be exactly 3 and its Superblock enum must be V3. Unknown enum ordinals fail deserialization. There is no required/optional feature bitmap, extension directory, generic unknown-record skip rule, or negotiated minor version.
3. Canonical root flags are zero, and unknown root bits are rejected. Canonical entry flags are zero for committed entries; current readers reject INCOMPLETE but retain/ignore other bits. Consequently, an unknown entry flag cannot safely signal a new required semantic to old readers.
4. Bincode trailing bytes inside a declared payload are accepted; padding is authenticated. This tolerance does **not** mean old readers understand appended fields, preserve them on rewrite, or can safely execute changed actions. Root/frame length prefixes permit bounded parsing, not arbitrary future semantics.
5. Changes that require different interpretation, introduce mandatory fields/records/features, change coordinate rules or cryptography, or alter mutation semantics need an explicitly designed new version and migration. A future optional extension must first define old-reader behavior, authentication coverage, size limits, and rewrite retention. Do not retrofit such a contract by silently reusing v3 reserved bytes.
6. Named KDF profiles are immutable. New encrypted-profile identifiers require out-of-band selection and authenticated validation; existing readers are not required to try unbounded profile parameters.
7. Legacy v2 remains readable/exportable/migratable and read-only through the current API. V3 creation does not rewrite an existing v2 region in place. Migration/export creates a fresh v3 destination. Public Rust names such as Journal2 and Superblock are not disk-version negotiation signals.

Representative complete-file encrypted golden fixtures, an independent decoder, sustained fuzzing, and total-allocation budgets remain separate follow-up work; the byte-level assertions and corruption/regression suite are the current executable compatibility checks.
