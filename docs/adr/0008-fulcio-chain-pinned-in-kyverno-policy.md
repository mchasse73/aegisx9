# 8. Pin the Fulcio certificate chain in the Kyverno keyless policy

- Status: Accepted
- Date: 2026-10-21

## Context

The first staging deployment was refused by the cluster's image-verification policy with
"certificate signed by unknown authority" although the image signature verified with
cosign v2 and v3 against the public Sigstore roots. A bisect with the Kyverno CLI at the
cluster's version showed two facts that combine: cosign v3 writes an empty certificate
chain annotation in the legacy signature layout (only the leaf is embedded, where cosign
v2 embedded Fulcio's intermediate), and Kyverno 1.17 configures only Fulcio's self-signed
roots from TUF and never its intermediate. The leaf therefore cannot chain. Controller TUF
settings, a custom root file, and ignoring the transparency log or the SCT do not help.

## Decision

- The keyless attestor in `policies/kyverno/verify-images.yaml` carries `roots` with the
  public Fulcio chain (intermediate plus roots). Rekor and certificate-transparency keys
  continue to come from TUF; transparency-log and SCT verification stay enforced.
- The release pipeline keeps signing with current cosign in the legacy layout
  (`--new-bundle-format=false --use-signing-config=false`) so the cluster's verifier finds
  the signature; downgrading the signer to cosign v2 to repopulate the chain annotation was
  rejected as tying the pipeline to an old tool.
- The platform team applies the same `roots` to the live policy. The intermediate is
  valid until 2031-10-05; a Fulcio rotation requires updating this file and the live policy,
  which is tracked as an operational note in the runbook.

## Consequences

- Admission verifies the full chain again, with no weakened checks.
- The chain is pinned rather than discovered; an upstream Kyverno change to load
  intermediates from TUF would remove the need for the pin.
