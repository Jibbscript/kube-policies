---
title: "Independent Code-Review Report — Kube-Policies (KP)"
control_family: "CA — Assessment, Authorization, and Monitoring; SA — System and Services Acquisition"
controls: "SA-11, CA-2, CA-8(1), RA-5"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-06-02"
next_review: "2027-06-02"
---

# Independent Code-Review Report — Kube-Policies (KP)

> **ILLUSTRATIVE / INTERNAL PRE-ASSESSMENT (pre-3PAO).** This is the self-attested
> internal review described in [docs/security/pen-test-plan.md](../../security/pen-test-plan.md);
> FedRAMP CA-8(1)/SA-11 require an INDEPENDENT 3PAO assessment which has NOT been
> performed. No ATO is asserted.

> **Honesty note.** KP is an as-built Proof-of-Concept being driven to assessment
> readiness; it is **not authorized** and is not in production use. This report records a
> **genuine internal code-review lane** that reviewed the codebase at the current branch
> baseline. The review lane is staffed by parties associated with KP development/operations
> and is therefore **separate** from — but **not independent of** — the development team in
> the FedRAMP CA-8(1) sense. Named roles below are placeholders ("TBD — assign"); do not
> infer individuals. Findings recorded here are **tracked in the POA&M**
> ([POA&M](../POAM.md), authoritative CSV [`poam.csv`](../poam.csv)); this report does not
> assign new POA&M identifiers (they are being assigned concurrently) and does not change
> per-control status, which remains authoritative in the
> [control matrix](../control-matrix.csv).

This report records the findings of the **code-review lane** of the internal P12-WU-04
pre-assessment. It is one of two complementary internal lanes; the security/pen-test-style
lane is recorded in the [Penetration-Test-Style Internal Review](pentest-report.md). The
scope, rules of engagement, and independence requirement that govern both lanes are defined
in the [Penetration Test Plan](../../security/pen-test-plan.md) and the assessment-wide
[Security Assessment Plan (SAP)](SAP.md). See the [compliance index](../README.md) for the
full document set.

---

## 1. Scope and method

The code-review lane performed a **manual, gray-box source review** of the KP Go codebase at
the current branch baseline, focused on correctness, concurrency safety, fail-mode handling,
and the integrity of the audit and admission paths. Method:

- Manual reading of the admission, policy-engine, configuration, audit, and decision-publish
  packages, cross-referenced against their unit and fuzz tests.
- `go vet` over the module (clean).
- Targeted review of concurrency primitives (pub/sub, ring buffer, rate limiter) and the
  TLS hot-reload path.

This lane does **not** substitute for the independent 3PAO code review / SA-11 developer
testing required for authorization (see § 6).

---

## 2. Overall assessment

The codebase is **unusually mature for a PoC**. Fail-mode handling is deliberate and tested
rather than incidental; the pub/sub, ring-buffer, and rate-limiter paths are race-clean; the
audit pipeline drains on shutdown; and TLS 1.3 material is hot-reloaded without restart. The
review surfaced **no Critical findings**. The two High findings are correctness/honesty
issues rather than exploitable defects — one of which was **remediated during this review
cycle**.

**Recommendation: COMMENT.** There are no Critical findings; both High findings are
correctness/honesty matters (one already remediated this cycle), and the remaining
Medium/Low findings are tracked in the POA&M for scheduled remediation. This internal review
does **not** constitute the independent SA-11 / CA-8(1) sign-off required for an
authorization decision.

**Finding summary: 0 Critical, 2 High, 4 Medium, 3 Low.**

---

## 3. Findings

Findings are severity-sorted. Each carries an affected component, an impact, a remediation,
and a status. Open findings are **tracked in the POA&M** ([POA&M](../POAM.md)); POA&M
identifiers are assigned concurrently and are intentionally not hard-coded here.

### 3.1 High

#### CR-H1 — Admission evaluation used an unbounded context (REMEDIATED this cycle)

- **Severity:** High
- **Status:** **Resolved** — remediated this cycle (evidence: P12-WU-04 remediation commit).
- **Component:** [`internal/admission/controller.go`](../../../internal/admission/controller.go)
- **Impact:** Admission evaluation was launched with `context.Background()` and no deadline,
  while the kube-apiserver enforces an admission webhook timeout of **≤ 10 s**. A slow or
  pathological evaluation could run past the apiserver's own cutoff, wasting work and risking
  resource pile-up under load with no in-binary backstop.
- **Remediation (applied):** Evaluation is now bounded to a **2 s** deadline derived from the
  inbound request via `context.WithTimeout`, so the engine cannot exceed the apiserver
  admission window.
- **Retest:** Re-reviewed post-fix; the bounded context is threaded into the engine call.

#### CR-H2 — `PolicyConfig.FailureMode` is a validated-but-ignored knob (OPEN)

- **Severity:** High
- **Status:** Open — **tracked in the POA&M**.
- **Component:** [`internal/config/config.go`](../../../internal/config/config.go) vs.
  [`internal/admission/controller.go`](../../../internal/admission/controller.go)
- **Impact:** `PolicyConfig.FailureMode` is parsed and validated at config load, but the
  admission controller **ignores it**: mutate is hardcoded fail-open (with a metric) and
  validate is hardcoded fail-closed. The documented `failure_mode` setting therefore does
  **nothing**, which is a configuration-honesty defect — an operator could believe they have
  changed fail behavior when they have not.
- **Remediation:** Either wire `FailureMode` through to the controller's fail-decision, or
  **remove** the knob and document the fixed fail-open-mutate / fail-closed-validate
  behavior explicitly.

### 3.2 Medium

#### CR-M1 — Engine holds the read lock across the full multi-policy OPA evaluation (OPEN)

- **Severity:** Medium
- **Status:** Open — **tracked in the POA&M**.
- **Component:** [`internal/policy/engine.go`](../../../internal/policy/engine.go)
- **Impact:** The engine holds an `RLock` for the entire multi-policy OPA evaluation. A CRD
  write (which needs the write lock) can be made to wait behind a long evaluation, and a
  burst of evaluations can stall a policy update — coupling admission latency to policy churn.
- **Remediation:** Snapshot the policy slice under the lock, release it, then evaluate
  lock-free against the snapshot.

#### CR-M2 — Decision publisher drops events under backpressure with no spool (OPEN)

- **Severity:** Medium
- **Status:** Open — **tracked in the POA&M**.
- **Component:** [`internal/admission/decision_publisher.go`](../../../internal/admission/decision_publisher.go)
- **Impact:** Under backpressure the decision publisher drops events with no on-disk spool.
  This is **telemetry-only** — the durable, integrity-chained audit log is a separate path
  and is **not** subject to this drop — but live decision-stream consumers can miss events
  during a burst.
- **Remediation:** Document the telemetry-only semantics and, if richer guarantees are
  needed, add a bounded spool or surface a drop metric for the decision stream.

#### CR-M3 — Audit correlation/request IDs synthesized from a nanosecond clock (OPEN)

- **Severity:** Medium
- **Status:** Open — **tracked in the POA&M**.
- **Component:** [`internal/audit/logger.go`](../../../internal/audit/logger.go)
  (`LogConfigChange` / `LogSystemEvent`)
- **Impact:** `LogConfigChange` and `LogSystemEvent` synthesize correlation/request IDs from
  `time.Now().UnixNano()`. Two events emitted within the same nanosecond tick collide,
  weakening audit traceability (AU-3/AU-10) for closely spaced events.
- **Remediation:** Generate IDs with a collision-resistant source (e.g. `uuid`).

#### CR-M4 — `require-image-digest` uses a substring match, not an anchored digest (OPEN)

- **Severity:** Medium
- **Status:** Open — **tracked in the POA&M**.
- **Component:** [`internal/policy/engine.go`](../../../internal/policy/engine.go)
- **Impact:** The `require-image-digest` rule matches the substring `@sha256:` rather than an
  anchored 64-hex-character digest. A crafted reference containing the substring but not a
  valid digest could pass. The rule is **opt-in**, which bounds exposure.
- **Remediation:** Replace the substring check with an **anchored regex** matching a full
  64-hex digest.

### 3.3 Low

#### CR-L1 — Vestigial `Manager.ctx`/`cancel`

- **Severity:** Low
- **Status:** Open — **tracked in the POA&M**.
- **Impact:** A `Manager.ctx`/`cancel` pair is carried but unused — dead state that invites
  future misuse. No current functional impact.
- **Remediation:** Remove the vestigial fields.

#### CR-L2 — Audit `Context.Object` aliases the live request payload across the async flush boundary

- **Severity:** Low
- **Status:** Open — **tracked in the POA&M**.
- **Component:** [`internal/audit/logger.go`](../../../internal/audit/logger.go)
- **Impact:** The audit `Context.Object` aliases the live request payload across the
  asynchronous flush boundary — a **latent** data-race/mutation hazard that is currently
  **masked** by the redaction deep-copy performed before serialization. If the redaction copy
  were ever removed or bypassed, the alias would become a real defect.
- **Remediation:** Deep-copy (or take ownership of) the object at capture time so correctness
  does not depend on the downstream redaction copy.

#### CR-L3 — `RecentDecisions` negative-limit handling relies on a downstream clamp

- **Severity:** Low
- **Status:** Open — **tracked in the POA&M**.
- **Impact:** `RecentDecisions` accepts a negative limit and relies on a **downstream clamp**
  to avoid misbehavior, rather than validating the input at the boundary. Robust today,
  fragile to refactor.
- **Remediation:** Validate/clamp the limit at the entry point.

---

## 4. Strengths recorded

The review explicitly recorded the following strengths so they are preserved as evidence and
not regressed:

- **Exception suppression fails closed on registry error** — a registry lookup failure does
  not silently suppress enforcement.
- **Audit shutdown is leak-free and lossless on drain** — the audit pipeline drains
  outstanding records on shutdown, and a **seal error does not fall back to an unchained
  write** (integrity is preserved over availability).
- **TLS reloader watches the mount directory** — it handles the `..data` atomic-swap symlink
  rotation used by Kubernetes secret mounts, so rotated TLS 1.3 material is picked up without
  restart.
- **Pub/sub uses a race-safe drop-oldest policy** — bounded, deterministic backpressure
  behavior under load.
- **mTLS enforce-by-default, fail-closed** — the webhook transport defaults to enforcing
  mTLS and fails closed.
- **90-day AU-11 retention floor enforced at config load** — the audit-retention minimum is
  validated at startup.
- **`go vet` clean** — no vet diagnostics over the module.

---

## 5. Retest note

The single remediated finding (**CR-H1**, admission eval context now bounded to 2 s) was
**re-reviewed after the fix** and confirmed: the bounded request-derived context is threaded
into the engine evaluation. No High or Critical finding remains unremediated. The remaining
Medium and Low findings are **tracked in the POA&M** for scheduled remediation within the
applicable SLA.

---

## 6. Independence and limitations (CA-8(1) / SA-11)

This is an **internal** code-review lane, useful for early finding discovery and
remediation, but conducted by parties associated with KP development/operations. It
therefore **does not satisfy** the FedRAMP **CA-8(1)** independence requirement or the
independent **SA-11** developer-testing-and-evaluation expectation on its own. An external,
independent code review / 3PAO assessment **must be performed** before an authorization
decision, as required by the [Penetration Test Plan](../../security/pen-test-plan.md) § 6 and
the [SAP](SAP.md). No authorization decision is asserted by this report.

---

## 7. Cross-links

- [Penetration Test Plan](../../security/pen-test-plan.md) — scope, RoE, methodology, and the CA-8(1) independence requirement governing this review.
- [Penetration-Test-Style Internal Review](pentest-report.md) — the companion security lane of P12-WU-04.
- [Security Assessment Plan (SAP)](SAP.md) — assessment-wide scope, methodology, schedule, and RoE.
- [POA&M](../POAM.md) · [`poam.csv`](../poam.csv) — where the open findings above are tracked.
- [Control Matrix](../control-matrix.csv) — authoritative per-control status and responsible party.
- [Compliance index](../README.md) — full compliance document set.
- FedRAMP Moderate baseline; NIST SP 800-53 Rev 5 (SA-11, CA-2, CA-8(1), RA-5).
