# Deferred plan: segment compaction

Date: 2026-09-05
Status: deferred design; implementation is not scheduled by this document.

## Purpose and agreed constraints

Add incremental space reclamation while preserving logfs's simple single-writer,
log-based structure and support for raw block devices.

- Reclamation must happen on the same device.
- Maintenance pauses are acceptable.
- Splitting the device into two alternating full-log regions is explicitly ruled
  out. A bounded reserve for cleaning is still necessary.
- Avoid complexity that is not justified by the workload.
- The workload mixes very small and very large values. The description
  "millions+" has not yet been clarified as key count versus value size; the
  design discussion considered millions of keys as a possible requirement.
- Device size, maximum live occupancy, maximum value size, churn, and use of
  encryption and streaming writes remain to be confirmed.

This records a direction for later work, not an approved on-disk specification.

## Existing structure to preserve

The v2 implementation uses a single writer, an in-memory `BTreeMap` mapping names
to value locations, and journal records for inserts, renames, deletes, and index
snapshots. Replay can restore a full snapshot and skip historical value payloads.
Large values support chunked encryption and streaming, but their chunks currently
occupy contiguous storage and their positions are inferred from that layout.

Relevant code:

- `logfs/src/journal/v2/data.rs`: persisted records and superblocks.
- `logfs/src/journal/v2/write.rs`: append and streaming write paths.
- `logfs/src/journal/v2/read.rs`: replay and value readers.
- `logfs/src/journal/v2/mod.rs`: opening, checkpoint restoration, and mutations.
- `logfs/src/state.rs`: in-memory index and obsolete-data estimates.

## Proposed structure

Divide the data area into reusable segments. Ordinary writes append into an
active segment; when it fills, the writer allocates a free segment. Deletes and
overwrites make old records obsolete without immediately modifying their bytes.

Start with explicit maintenance cleaning. Pause operations, drain existing
readers and writers, and prevent independent writers from opening the device.
This avoids concurrent relocation and reader-lifetime management in the first
implementation.

Initially favor source segments with substantial reclaimable space. Use a simple
selection policy before considering workload classification or background work.
Segment size, record framing, allocation metadata, and the representation of
segment generations remain design decisions.

## Reclamation protocol and invariants

The required order is **copy -> persist -> publish -> reuse**:

1. Select a bounded group of source segments and identify their live contents
   from authoritative logical state.
2. Copy surviving data and required metadata into free destination segments.
3. Synchronize the destination records.
4. Durably publish replacement locations and retirement of the source segments
   as one recoverable transition.
5. Make retired segments available for reuse only after publication is durable
   and no active reader can reference their old contents.

The detailed commit mechanism is unresolved. Whatever mechanism is chosen must
maintain these invariants:

- Never overwrite the only recoverable copy of live data or required metadata.
- Before relocation publication, source locations remain authoritative.
- After publication, replacement locations are authoritative; replay must not
  depend on the retired contents.
- Physical relocation must not become a logical user update. It must not
  resurrect deleted names, undo renames, or supersede newer values.
- Destination copies from interrupted cleaning must be distinguishable from
  committed live records and eventually reclaimable.
- Recovery must distinguish segment incarnations so stale pointers and old
  records cannot refer to newly reused storage.
- Recovery roots eligible for fallback must not depend on overwritten segments.
  Redundant roots and their retirement protocol must preserve this property.

These are requirements, not assumptions that individual device writes are atomic.

## Small and large values

Keep a simple single-location representation for small values where possible.
Large values should have independently movable chunks, so reclaiming one segment
does not require copying an entire large value.

Existing chunking is a starting point, but a compact extent or chunk-location
representation is needed once chunks cease to be contiguous. Choose that
representation only after confirming maximum value sizes and index-memory
constraints. Avoid an allocation object per tiny value if ordinary packed records
can serve the same purpose.

Logical identity and version must be separate from physical location. In
particular, an original insert record can contain an obsolete name after a rename;
copying and replaying that insert as a fresh operation is incorrect.

If encryption is enabled, specify how chunk identity, authentication, and nonce
uniqueness survive relocation, segment reuse, interrupted writes, and reopening.
Neither reuse of a physical offset nor restart of a sequence is sufficient to
establish safe nonce uniqueness under an existing key.

## Checkpoints and recovery

After reclamation, replaying all remaining records from the physical beginning is
not a valid general recovery strategy: older deletes, renames, or other required
history may already have been reclaimed. Recovery needs an authoritative
checkpoint and a defined subsequent logical journal.

Do not require a full million-key checkpoint for every cleaned segment. Evaluate:

1. Publishing a bounded group of relocated segments with one full checkpoint.
2. Compact relocation commits between periodic full checkpoints.

Prefer the first if its write volume, reserve requirement, and maintenance time
are acceptable. The second needs a precise, bounded replay and metadata-retention
protocol. This choice must precede finalizing the format.

Checkpoint records and journal metadata also occupy space and need explicit
liveness and reclamation rules. Publishing a new checkpoint must not prematurely
free records needed by a still-eligible recovery root.

Consider streaming checkpoint serialization in bounded chunks to reduce peak
memory. Retain full logical snapshots initially; partial namespace checkpoints
and an on-disk search tree are separate features.

## Capacity and accounting

Reserve space that ordinary writes cannot consume. Derive the minimum from the
maximum relocation group, live destination data, checkpoint or relocation commit,
root publication, and any records required to recover an interrupted attempt.
The required amount depends on the unresolved publication protocol; do not assume
one free segment or an arbitrary percentage is sufficient.

Track live, obsolete, free, and reserved bytes separately, including metadata,
padding, and encryption overhead. Account for overwrites and rename destinations
as well as explicit deletes. Persist authoritative allocation state or make it
reconstructible from committed records; estimates alone cannot authorize reuse.

At high live occupancy, cleaning may reclaim little space and incur substantial
copying. Return a clear capacity error when no safe useful cleaning operation fits
within the reserve. The design cannot promise continued growth when live contents
and required metadata consume available capacity.

## Prerequisites

Address the existing correctness issues before adding reuse:

- Define durable commit ordering and synchronization boundaries.
- Fix checkpoint fallback so it resets all replay state.
- Apply checkpoint scheduling to streaming completion as well as other writes.
- Unify mutation locking and recover writer ownership on error.
- Correct readonly enforcement, empty-value behavior, and base-offset handling.
- Validate records, checksums, bounds, and committed replay boundaries.
- Correct encryption nonce reuse in mutable superblocks and streaming metadata.
- Enforce backing-region bounds and exclusion of independent writers.

Use an explicitly versioned format and preserve a v2 reading/migration path.
Migration itself is an unresolved task: existing v2 data may fill the device and
may not leave enough scratch space for a safe same-device conversion. Do not claim
that segment cleaning automatically solves initial format migration.

## Suggested implementation sequence when resumed

1. Confirm capacity, occupancy, value-size distribution, and maintenance budget.
2. Specify record/chunk identity, segment generations, allocation state,
   publication, recovery fallback, and the required reserve together.
3. Implement the prerequisites and a small storage interface for fault injection.
4. Implement segmented append and recovery without reclamation, with format tests.
5. Add explicit maintenance cleaning with one simple selection policy.
6. Add accounting, progress reporting, capacity errors, and migration tooling.
7. Benchmark representative workloads before adding further optimizations.

Keep background cleaning, concurrent compaction, hot/cold placement, general
variable-size allocation, partial namespace checkpoints, and an on-disk index out
of the initial scope.

## Validation and acceptance

- Compare logical contents against a reference map across inserts, overwrites,
  renames, deletes, batches, cleaning, and reopening.
- Inject interrupted and partial writes and synchronization failures at every
  relocation/publication/reuse boundary. Include reordered persistence where the
  protocol does not establish a barrier.
- Exercise corrupt roots/checkpoints, stale segment generations, interrupted
  destination copies, and repeated reuse of the same segments.
- Verify that deleted names stay deleted and renames survive relocation.
- Cover empty/tiny values, maximum-size chunks, multi-segment values, encryption,
  streaming, and nonzero backing-region offsets.
- Exercise reserve exhaustion and nearly full devices; failures must preserve
  committed data and must not leave an unrecoverable allocation state.
- Measure reclaimed bytes, bytes copied, metadata write volume, peak memory,
  maintenance duration, and checkpoint/tail replay time.

Acceptance requires preservation of acknowledged durable operations under the
documented storage-failure model, correct reclamation across repeated cycles,
bounded maintenance resource use, and an explicitly documented capacity reserve.
