# Unreleased

* Replace the unreleased development v3 formats with opaque fixed-size roots
  and journal framing. Encrypted v3 exposes only random Argon2id salts,
  XChaCha20-Poly1305 nonces, ciphertext, and unavoidable size/growth leakage;
  old development v3 is intentionally not accepted.
* Add fixed named Argon2id profiles and HKDF-separated entry, checkpoint, and
  history keys rooted in a random per-log secret. Authenticate slot/generation
  pairs, checkpoint boundaries, and a keyed history chain to reject root,
  entry, and sibling-history substitution.
* Keep legacy v2 available through a read-only inspection/export path and make
  compaction the explicit migration into a freshly created v3 destination.
* Add exclusive non-durable creation and optional randomized bounded-region
  initialization while preserving bytes outside the configured region.
* Fix encrypted legacy-v2 empty writes, bound checkpoint payloads before
  allocation, and stream scrub/compaction verification.
* Allow checkpoint-restored v2 data to be compacted with its available integrity
  coverage, make repair/compact destination creation exclusive, use locked
  descriptor metadata for format decisions, and initialize CLI tracing once.
* Random-fill transparent root/header padding and incomplete streaming
  reservations; keep plaintext-v3 metadata checksummed and retain value hashes
  in v3 checkpoints.
* Fix checkpoint fallback, committed-tail validation, streaming at nonzero
  offsets, empty values, readonly/create enforcement, batch ordering, writer
  lifecycle errors, and obsolete-value accounting.
* Add explicit checkpoints, scrub, flush/sync, durable-open, bounded-region and
  occupied-log-size APIs. The historical buffered default is unchanged.
* Always store value hashes while making routine whole-value hash checking an
  additive opt-in policy; scrub still verifies and reports unavailable legacy
  coverage separately.
* Keep reads tied to the opened backing object, add cooperating file locks,
  remove quadratic large-value chunk splitting, and harden repair/export paths.
* Invalid/corrupt committed records now return errors instead of panicking,
  hanging, allocating from out-of-region lengths, or silently publishing partial
  state. Automatic-checkpoint failures after a committed mutation are logged
  instead of making the mutation look retryable.

# v0.1.1 - 2025-09-16

* Fixes a significant bug that could cause deadlocks due to the writer not
  being returned to the state
* Fixes another potential deadlock issue by making sure the different locks
  are always acquired in a consistent order

# v0.1 - 2025-09-16

Initial release.
