# Verified security maintenance

Security-only proposals use the pinned Lanrith maintenance workflows. They record
the advisory, exact changed input digests, policy and tool revision. The independent
reviewer fetches the actual PR bytes and GitHub validation results. Approval remains
disabled during the report-only pilot. Workflow, policy, native source and module
migrations require human review.

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
