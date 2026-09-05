# Unreleased

* Add the v3 authenticated/checksummed root envelope, per-entry encrypted nonce
  domains, and v3 checkpoints that retain value-integrity metadata while keeping
  legacy v2 decoding intact.
* Place v3 roots in separate absolute 4 KiB-aligned slots, bind encrypted entry
  framing to the random file identity, and checksum plaintext v3 metadata.
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
