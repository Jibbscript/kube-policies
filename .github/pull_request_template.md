<!--
Configuration change-control checklist (NIST CM-3 / CM-4).
This template is the CM-3 change-control record for Kube-Policies. The
Configuration Management Plan (docs/compliance/plans/configuration-management-plan.md)
and CM procedures (docs/compliance/procedures/CM-procedures.md) require it to be
completed for any change to a configuration item (Helm chart, CRDs, base manifests,
runtime config, images, or the compliance artifacts that record them).
-->

## Summary

<!-- What does this PR change and why? Link the issue / work unit. -->

## Type of change

- [ ] Bug fix
- [ ] Feature
- [ ] Configuration item change (Helm chart / CRD / base manifest / runtime config / image)
- [ ] Documentation / compliance artifact
- [ ] CI / tooling

## Configuration change-control checklist (CM-3)

> Complete this for any change that touches a configuration item. If a box does
> not apply, check it and note "n/a — <reason>". Reviewers must not approve a CI
> change with an unchecked, unexplained box.

- [ ] **Baseline updated.** If this changes a configuration setting, the
      [secure configuration baseline](../docs/compliance/secure-configuration-baseline.md)
      (CM-2 / CM-6) was updated to match — or this change introduces no baseline-setting change (n/a).
- [ ] **Inventory updated.** If this adds/removes/renames a component, image, or
      listening port, the [component inventory](../docs/compliance/inventory.md) and the
      [ports/protocols register](../docs/compliance/ssp/ports-protocols-services.md) were
      updated — or no component/port changed (n/a).
- [ ] **Policy gates green.** The gating CI jobs pass: `manifest-hardening-gate`
      (restricted-PSS), `helm-unittest`, `network-posture-gate`, `rbac-sa-gate`, and the
      gating Trivy scan (`CRITICAL,HIGH` fail the build). A change that weakens the
      baseline (removing a `seccompProfile`, a NetworkPolicy, an RBAC scope, etc.) must
      not be merged.
- [ ] **Image digest pinned.** If this changes a deployed image reference, it is
      **digest-pinned** (`tag@sha256:…`) where the deployment target requires it — or this
      change does not alter an image reference (n/a). (Note: shipped `values.yaml` still uses
      floating tags by default — residual POAM-023.)
- [ ] **Security impact (CM-4).** The security impact of this change has been
      considered and noted below; security-relevant changes (boundary, RBAC, NetworkPolicy,
      TLS/crypto, CRD schema) are flagged for CCB / ISSO review.
- [ ] **Tests / verification.** Unit/conformance/e2e tests added or updated as needed,
      and `make validate-compliance` passes if a compliance artifact changed.

### Security impact note (CM-4)

<!-- Describe the security impact, or "none — <reason>". Flag if CCB / ISSO review is required. -->

## Verification

<!-- Commands run, gate output, screenshots, or links to CI runs that demonstrate the change works. -->
