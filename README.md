# logfs

A simple userspace file system implementation based on an append-only log.

Supports optional encryption and compression.

> [!CAUTION]
> Note: the encryption is not audited - use at your own risk.

## Storage and durability

New logs use two opaque 4 KiB root slots at the configured region offset. An
encrypted slot exposes only an independent random 128-bit Argon2id salt, a
random 192-bit XChaCha20-Poly1305 nonce, and ciphertext. Version, KDF profile,
128-bit log identity, physical slot, generation, committed tail, checkpoint,
random per-log secret, and history commitments are inside the authenticated
payload. The slots require adjacent, parity-consistent generations and matching
identity, secret, and salts. A corrupt, substituted, or truncated slot is an
error rather than permission to silently select older acknowledged state. This
detects local root substitution; restoring both slots and their journal from an
older snapshot remains outside the format's rollback guarantees without trusted
external state.

Encrypted v3 roots use the out-of-band named `CryptoProfile` (`Standard`: 64 MiB,
three passes, one lane; `LowMemory`: 8 MiB, three passes, one lane). The profile
is redundantly authenticated inside the root. `CryptoConfig::salt` and
`iterations` remain inputs only to the isolated legacy-v2 PBKDF2 reader.
The authenticated per-log secret is expanded with HKDF-SHA256 into separate
entry, checkpoint, and history keys. Journal frames use random nonce seeds,
fixed-size encrypted headers, purpose-separated nonces, and a keyed history
chain whose committed tip and checkpoint boundary are authenticated by the
root. Consequently an entry or checkpoint from a sibling history cannot be
transplanted even when both histories originated from the same byte-for-byte
snapshot.

The obsolete development v3 formats are intentionally unsupported and are
never selected as a fallback after authentication failure. Legacy v2 remains
available through a read-only compatibility path for inspection and explicit
`compact` export into a freshly created v3 log.

`LogFs::open` retains buffered compatibility semantics: a successful mutation is
visible in-process and its root has been flushed, but this does not promise
survival of power loss. `LogFs::open_durable` or `LogOpenOptions { durable: true,
.. }` uses ordered commits: records are flushed and synchronized before the root
which acknowledges them is written and synchronized. A synchronization error
has an indeterminate durability outcome and taints further writes. Filesystem
directory-entry durability and hardware which ignores flushes remain platform
responsibilities.

Use `LogFs::create_new` or `create_new_durable` when initialization must be
exclusive. `open` never reformats a non-empty region: even when the legacy
`allow_create` option is enabled, an authentication or format error is returned
without modifying the bytes. The CLI's `--create` flag is the corresponding
explicit initialization request.

Only one cooperating writable handle may be open. Multiple readonly handles can
coexist, but they are snapshots established at open and are not live views.
Locks are advisory and cannot protect against non-cooperating programs.

`flush()` drains Rust buffering; `sync()` establishes an explicit OS-backed
durability boundary. `checkpoint()` writes a full snapshot immediately, while a
configured interval of zero disables automatic checkpoints. Streaming writers
retain commit-on-drop compatibility, but callers—especially CLI tools—should
call `finish()` so errors are observable.

For raw devices or files containing other data, `LogFs::open_with_options` can
bound the log to `region_len` bytes beginning at `LogConfig::offset`. Writes are
checked incrementally and bytes outside the region are not modified. Formatting
an existing region is only performed when the backing file ends exactly at the
configured offset and `allow_create` is enabled. Setting
`LogOpenOptions::randomize_region` during initialization writes random bytes to
all otherwise-unused capacity in the bounded region; it requires `region_len`
and is rejected for existing logs. Ordinary growing encrypted files avoid
fixed markers and reserved zero gaps, but still reveal total size and growth
timing. Randomized bounded regions hide unused capacity at the cost of a
full-region initialization write.

Whole-value hashes are always generated and stored for new values. Routine reads
skip hash checking by default for throughput; use
`LogFs::open_with_integrity(..., ReadIntegrity::VerifyHash)` or
`set_read_integrity` to verify at complete EOF. Structural framing checks and
encrypted chunk authentication are mandatory in every mode. `scrub()` always
requests all available verification and reports verified and unverifiable counts
separately while consuming values incrementally. A legacy v2 checkpoint omitted value hashes, so plaintext values
restored solely from one are reported as unverifiable rather than counted as
verified. Compaction can still migrate such values using all integrity available
in the source format, and the destination stores and verifies new whole-value
hashes. Partial reads and chunk iteration do not claim whole-value verification
before EOF.

Checkpoint payloads are capped at 512 MiB of decoded working memory, and journal
actions at 512 MiB, to reject corrupt length fields before unbounded allocation.

## Objstore backend

The `objstore_logfs` workspace crate provides a LogFS backend for `objstore`.
Its URI accepts an optional on-disk format constraint and a byte offset, for
example:

```text
logfs:///absolute/path/to/archive.log?version=3&offset=4096&create
```

`version` may be `2` or `3` when opening an existing log; new logs can only be
created as version 3. If `version` is omitted, the format is auto-detected.
`offset` selects the start of the LogFS region within the backing file. Offset
and block-device URIs default to read-only; the explicit `create` flag permits
initialization and writes. `allow_create=true` remains available as a verbose
alias.

## Performance harness

`cargo bench -p logfs --bench reliability --locked` covers 10,000 small writes,
a 32 MiB write, a full checkpoint, and a hash-verified 32 MiB read. One local
Linux release run during this change measured 175 ms, 26 ms, 2 ms, and 28 ms
respectively. These numbers are a regression baseline, not portable throughput
claims; storage, CPU, and synchronization policy materially affect them.
