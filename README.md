# logfs

A simple userspace file system implementation based on an append-only log.

Supports optional encryption and compression.

> [!CAUTION]
> Note: the encryption is not audited - use at your own risk.

## Storage and durability

New logs use two independently placed roots whose starts are aligned to absolute
4 KiB boundaries. Each redundant v3 envelope carries duplicate format markers,
a 128-bit random log identity, and a generation, and is authenticated when
encryption is enabled (or checksummed otherwise). A corrupt or truncated v3 root
is an error rather than permission to silently select older acknowledged state.
The roots use random 96-bit nonces; an encrypted identity is limited to 2^32 root
publications, giving a birthday-collision bound of approximately 2^-33. Creating
2^32 independent logs gives the 128-bit identities a collision bound of
approximately 2^-65.

Encrypted entries bind their file identity and chunk framing as AEAD associated
data. Entry nonce domains are reserved in a root and synchronized before their
ciphertext is written. Writable opens choose a fresh random 64-bit domain base,
so diverging byte-for-byte copies do not deterministically reuse entry nonces.
The remaining probabilistic limitation is explicit: for `S` independently
opened copies and at most `L` sequential domains consumed by each, the overlap
bound is approximately `S²L / 2^65`; export to fresh logs well before that is a
meaningful risk for the deployment. Existing
v2 logs, including their original PBKDF2 and chunk framing, remain readable and
writable through an isolated legacy path. Legacy encrypted writes retain v2's
historical nonce limitations; export to a fresh file to obtain v3 framing.

`LogFs::open` retains buffered compatibility semantics: a successful mutation is
visible in-process and its root has been flushed, but this does not promise
survival of power loss. `LogFs::open_durable` or `LogOpenOptions { durable: true,
.. }` uses ordered commits: records are flushed and synchronized before the root
which acknowledges them is written and synchronized. A synchronization error
has an indeterminate durability outcome and taints further writes. Filesystem
directory-entry durability and hardware which ignores flushes remain platform
responsibilities.

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
configured offset and `allow_create` is enabled.

Whole-value hashes are always generated and stored for new values. Routine reads
skip hash checking by default for throughput; use
`LogFs::open_with_integrity(..., ReadIntegrity::VerifyHash)` or
`set_read_integrity` to verify at complete EOF. Structural framing checks and
encrypted chunk authentication are mandatory in every mode. `scrub()` always
requests all available verification and reports verified and unverifiable counts
separately. A legacy v2 checkpoint omitted value hashes, so plaintext values
restored solely from one are reported as unverifiable rather than counted as
verified. Partial reads and chunk iteration do not claim whole-value verification
before EOF.

Checkpoint payloads are capped at 512 MiB of decoded working memory, and journal
actions at 512 MiB, to reject corrupt length fields before unbounded allocation.

## Performance harness

`cargo bench -p logfs --bench reliability --locked` covers 10,000 small writes,
a 32 MiB write, a full checkpoint, and a hash-verified 32 MiB read. One local
Linux release run during this change measured 62 ms, 26 ms, 1 ms, and 29 ms
respectively. These numbers are a regression baseline, not portable throughput
claims; storage, CPU, and synchronization policy materially affect them.
