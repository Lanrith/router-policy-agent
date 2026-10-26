# Verified security maintenance

Security-only proposals use the pinned Lanrith maintenance workflows. They record
the advisory, exact changed input digests, policy and tool revision. The independent
reviewer fetches the actual PR bytes and GitHub validation results. Approval requires
both enforcement mode in the protected policy and the repository approval flag.
The flag stays disabled until the platform and both component policy changes
are reviewed, qualified and merged, and the final configuration checks pass.
Workflow, policy, native source and module migrations require human review.

The compiler is pinned in `.go-version`. Dependency updates remain on the existing
stable patch line and retain Go checksum verification. Full component qualification,
source and binary vulnerability scans precede publication. The publisher stages
attested assets in a draft, seals the release, checks every digest and its source tag,
then promotes it to stable. It retains the approved PR and exact validation history
in `update-record.json`; a separately attested publication record binds the immutable
release assets. Lanrith's component pin includes this record's digest, preserving the
trace from a component fix into the platform build.

Actions artifacts are temporary handoffs with one-day retention. Cleanup archives
its plan before deleting completed handoffs, rechecks every identity, and preserves
active runs and durable release assets. Paid AI services are not used.

See [the owner setup and audit instructions](https://github.com/Lanrith/lanrith/blob/main/docs/security-maintenance.md).

Cleanup skips empty inventories. Its own small audit handoffs expire after one day, so removing them does not generate another set of audit records.

The publisher verifies a human reviewer's current write or admin access directly.
Private organisation membership can appear as contributor status to an
installation token; that display value does not establish review authority.

The proposer, reviewer, release collector, publisher and cleanup workflows pin
the same protected Lanrith commit. The remediation record links that commit
to its immutable release, signed assessment and actual approval history.
Admission stays in progress while required validation is unfinished, then
rechecks on completion. Pending, failed, cancelled, skipped or stale
validation cannot grant automatic approval or permit a merge.
