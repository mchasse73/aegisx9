# 2. GitHub, GHCR and keyless image signing

- Status: Accepted
- Date: 2026-10-21

## Context

The project will become public. It needs hosted source control, issue tracking, CI and a
container registry that outside readers can see, plus a supply chain that a cluster can
verify without managing long-lived signing keys.

## Decision

- Source, issues, milestones and the project board live on GitHub (`mchasse73/aegisx9`).
- CI/CD runs on GitHub Actions using GitHub-hosted runners for all build and scan work.
  Every third-party action is pinned to a full commit SHA and updated by Dependabot.
- Images are pushed to GHCR (`ghcr.io/mchasse73/aegisx9`). They are built once on `main`;
  version tags re-tag the already-signed digest instead of rebuilding.
- Images are signed **keylessly** with cosign through Sigstore: the release job requests a
  GitHub OIDC token (`id-token: write`), Fulcio issues a short-lived certificate bound to
  the workflow identity
  `https://github.com/mchasse73/aegisx9/.github/workflows/release.yml@refs/heads/main`,
  and the signature is logged in Rekor. A Syft SPDX SBOM is attached as a cosign
  attestation, and build provenance is attested with GitHub artifact attestations.

## Consequences

- No signing keys to store, rotate or leak.
- Verification depends on the public Sigstore infrastructure (Fulcio, Rekor) being reachable
  from the cluster's admission controller.
- The signer identity is tied to the workflow path and branch; renaming the workflow or the
  repository requires updating the Kyverno policy in the same PR.
