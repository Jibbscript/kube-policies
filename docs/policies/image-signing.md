# Image Signing & Admission Enforcement (SUP-WU-07)

Controls: NIST CM-14, SR-4, SR-11 | NIST SP 800-190 §4.3

This document describes the two layers of admission-time image enforcement
available in kube-policies and is honest about what each layer does and does
not verify.

---

## Architecture: two complementary layers

There are two distinct enforcement mechanisms. They are designed to stack:

| Layer | What it checks | How it works | Default state |
|-------|---------------|--------------|--------------|
| **In-process webhook policy** (`image-provenance`) | Allowed registries + digest pinning | Bundled Rego rules evaluated by the admission webhook's in-process OPA engine | **Disabled** (opt-in) |
| **Sigstore policy-controller ClusterImagePolicy** | Cryptographic cosign signature verification | External admission webhook provided by the Sigstore policy-controller | **Disabled** (opt-in; requires separate controller install) |

Neither layer is enabled by default. They are independent — you can enable
either or both.

---

## Layer 1: in-process image-provenance policy

### What it enforces

The bundled `image-provenance` policy (`internal/policy/engine.go`,
`examples/policies/image-provenance.yaml`) enforces two rules at admission time:

1. **`allowed-registries`** — every container image must have a prefix that
   appears in the configured allowed-registries set. By default the set
   contains only `ghcr.io/jibbscript/`; operators must expand this to their
   actual trusted registries.

2. **`require-image-digest`** — every container image reference must include an
   immutable `@sha256:` digest. A mutable tag alone is not acceptable because
   it does not uniquely identify the image that was inspected or scanned.

### What it does NOT enforce

This policy does **not** perform cryptographic cosign signature verification.
It cannot confirm that an image was built by a specific pipeline or signed by a
specific key. It enforces structural properties of the image reference, not
cryptographic provenance. Cryptographic signature verification is the
responsibility of Layer 2 (below).

### Enabling the in-process policy

The policy is registered in the engine at startup but is disabled by default
(`Enabled: false`). Enable it by applying the operator-customised example:

```bash
# Edit examples/policies/image-provenance.yaml first:
#   - Set allowed_registries to your trusted registry prefixes
#   - Confirm enforcement: true
kubectl apply -f examples/policies/image-provenance.yaml
```

Alternatively, enable the policy programmatically via the policy-manager API
by PATCHing the `image-provenance` policy's `enabled` field to `true`.

Once enabled, any pod admission request whose containers reference an image
from an unlisted registry or without a digest will be rejected with an
explanatory message.

### Testing that it rejects untrusted images

```bash
# This should be rejected (no digest, wrong registry):
kubectl run test --image=docker.io/library/nginx:latest --dry-run=server

# This should be admitted (digest present, trusted registry — adjust to yours):
kubectl run test \
  --image=ghcr.io/jibbscript/kube-policies/admission-webhook@sha256:<digest> \
  --dry-run=server
```

---

## Layer 2: Sigstore policy-controller ClusterImagePolicy

### What it enforces

When `imageVerification.enabled=true` in `values.yaml`, the chart renders a
`ClusterImagePolicy` object (YAML:
`charts/kube-policies/templates/image-verification-policy.yaml`). This object
instructs the Sigstore policy-controller admission webhook to:

- Intercept pod admission requests for images matching the configured glob
  patterns (default: `ghcr.io/jibbscript/kube-policies/**`).
- Require that each matching image carries a valid keyless cosign signature
  issued to the GitHub Actions OIDC identity of `release.yml`.
- Reject (mode: `enforce`) or audit (mode: `warn`) pods whose images lack a
  valid signature.

The trust anchor is:

```yaml
identities:
  - issuer: "https://token.actions.githubusercontent.com"
    subjectRegExp: "^https://github.com/Jibbscript/kube-policies/.github/workflows/release.yml@refs/tags/v.*$"
```

This means only images signed by this project's release pipeline on a release
tag will be admitted. Images signed by a fork, a different workflow, or a
development branch will be rejected when mode is `enforce`.

### Prerequisite

The Sigstore policy-controller must be installed in the cluster before enabling
`imageVerification`. The `ClusterImagePolicy` object is inert without it.

Install the policy-controller:
<https://docs.sigstore.dev/policy-controller/installation/>

### Enabling image signature verification

```yaml
# values.yaml or overlay
imageVerification:
  enabled: true
  oidcIssuer: "https://token.actions.githubusercontent.com"
  identityRegexp: "^https://github.com/Jibbscript/kube-policies/.github/workflows/release.yml@refs/tags/v.*$"
  imagePatterns:
    - "ghcr.io/jibbscript/kube-policies/**"
  mode: "warn"   # start in warn, flip to enforce once confirmed working
```

Start with `mode: warn` so that admission decisions are logged but not blocked
while you confirm that signed images are correctly recognised. Then flip to
`mode: enforce`.

### Testing that unsigned images are rejected

With `mode: enforce` active and the policy-controller running:

```bash
# An image with no cosign signature should be rejected:
kubectl run test \
  --image=ghcr.io/jibbscript/kube-policies/admission-webhook:latest \
  --dry-run=server
# Expected: admission webhook denied the request

# A correctly signed release image (once a release is cut) should be admitted:
kubectl run test \
  --image=ghcr.io/jibbscript/kube-policies/admission-webhook@sha256:<digest> \
  --dry-run=server
# Expected: admitted
```

---

## Honest status summary

| Capability | Status |
|-----------|--------|
| `image-provenance` policy (allowed-registries + digest pinning) | Implemented; disabled by default; opt-in via `examples/policies/image-provenance.yaml` |
| Sigstore ClusterImagePolicy (cosign signature verification) | Implemented; disabled by default (`imageVerification.enabled=false`); requires policy-controller |
| Any enforcement active by default | No — both layers are opt-in |
| Signed release images available | No — no release tag has been cut yet |

This project is pre-1.0. No ATO has been granted. Claims in this document
reflect what is implemented in code, not a certification status.

---

## Related documents

- `docs/supply-chain/verification.md` — verifying a release before deploy
- `docs/supply-chain/chart-verification.md` — verifying the Helm chart
- `docs/supply-chain/build-hardening.md` — SLSA L3 build isolation
