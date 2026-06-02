# Security Policy

Kube-Policies (KP) is a Kubernetes admission-control and policy-management system
(`github.com/Jibbscript/kube-policies`) being driven toward a FedRAMP-Moderate
authorization. This document is the project's **coordinated vulnerability disclosure
(CVD) policy**: how to report a vulnerability privately, what response you can expect,
and the remediation timelines we commit to. It is reviewed at least **annually**
(next review **2027-05-29**) and on every material change to the disclosure process.

> **Honest status.** Kube-Policies is presently a Proof-of-Concept being hardened to
> assessment readiness. Most security controls are **Planned** or **Partial**; the open
> weaknesses are tracked in the [POA&M](docs/compliance/POAM.md). The SLAs below describe
> the program we are standing up (phase **P11**, see below), not a claim that the program
> is already operating at steady state.

## Supported versions

Kube-Policies has not yet cut a General Availability (1.0) release. Until a stable line
exists, security fixes are produced only against the default branch (`main`) and the most
recent pre-release tag. There is no long-term-support (LTS) commitment for pre-1.0
artifacts.

| Version / line        | Status                 | Receives security fixes |
|-----------------------|------------------------|-------------------------|
| `main` (development)  | Active development      | Yes — fixes land here first |
| Latest `0.x` pre-release | Pre-release / PoC    | Yes — backported from `main` on a best-effort basis |
| Older `0.x` tags      | Superseded             | No — upgrade to the latest line |
| Any `*-rc`, `*-alpha`, `*-beta` build | Not supported | No |

When a GA (`1.x`) line is published, this table will be updated to define the supported
major/minor lines and their support windows. Container image supply-chain provenance,
signing, and digest pinning are tracked separately in phases P6/P11 of the
[Production Readiness Plan](.omc/plans/PRODUCTION-READINESS-FEDRAMP-CIS.md).

## Reporting a vulnerability

**Please do not open a public GitHub issue, pull request, or discussion for a suspected
security vulnerability.** Use one of the private channels below so we can triage and
remediate before any public disclosure.

### Preferred: GitHub private vulnerability reporting

Report privately through GitHub's built-in **"Report a vulnerability"** workflow, which
creates a private security advisory visible only to you and the maintainers:

- Go to the repository **Security** tab → **Advisories** → **Report a vulnerability**, or
- Open <https://github.com/Jibbscript/kube-policies/security/advisories/new>.

This is the channel we prefer because it keeps the report, the coordination thread, and
any draft fix private until we jointly publish.

### Alternate: email

If you cannot use GitHub private reporting, email the security contact:

- **Security contact:** `security@TBD` *(placeholder — the project security mailbox is
  TBD; it will be assigned before assessment, alongside the ATO roles tracked in
  [POAM-018](docs/compliance/POAM.md)).*

Encrypt sensitive details where possible. If the report contains exploit code or
customer-impacting detail, say so explicitly in the subject.

### What to include

To help us triage quickly, please include as much of the following as you can:

- The affected component and version/commit — name the asset where you can
  (`AST-WH` admission-webhook `:8443`/`:9090`, `AST-PM` policy-manager `:8080`/`:9091`,
  `AST-DB` dashboard BFF `:8090`/`:9092`, `AST-SPA`, `AST-OPA`, the `Policy`/`PolicyException`
  CRDs `AST-CRD-POL`/`AST-CRD-EXC`, or the Helm chart `AST-CHART`).
- A description of the vulnerability and its security impact (e.g. authentication bypass,
  policy-enforcement bypass, RCE, information disclosure, denial of service).
- Reproduction steps, a proof-of-concept, and affected configuration/manifests.
- Any known mitigations or workarounds.

## Response targets and remediation SLAs

We operate the disclosure process on the timelines below. SLA clocks start from the
**date we acknowledge a valid report** (for disclosures) or from the **scan/detection
date** (for internally found flaws). The remediation targets are aligned to the **FedRAMP
Moderate** continuous-monitoring remediation timelines and to NIST SP 800-53 Rev 5
**RA-5** (vulnerability scanning), **SI-2** (flaw remediation), and **CA-5 / PM-4**
(POA&M).

### Response (coordination) SLAs

| Stage              | Target                                  |
|--------------------|-----------------------------------------|
| Acknowledge receipt | **3 business days**                    |
| Triage & severity decision | **10 calendar days** from acknowledgement |
| Status updates     | At least every **10 calendar days** until resolution |

### Remediation SLAs by severity

Severity is assigned by the maintainers at triage using CVSS v3.1 base score as the
primary input, adjusted for exploitability and exposure in a typical deployment.

| Severity  | CVSS (guideline) | Remediation target (from acknowledgement / detection) |
|-----------|------------------|-------------------------------------------------------|
| Critical  | 9.0 – 10.0       | **30 days**  |
| High      | 7.0 – 8.9        | **30 days**  |
| Moderate  | 4.0 – 6.9        | **90 days**  |
| Low       | 0.1 – 3.9        | **180 days** |

"Remediation" means a fix is released, or a documented, validated compensating control or
risk-acceptance decision is recorded in the [POA&M](docs/compliance/POAM.md). Where a fix
cannot land within the target, the slippage and its justification are recorded as a POA&M
milestone and escalated to the System Owner / Authorizing Official (roles **TBD — assign
before assessment**).

## Coordinated disclosure and embargo

We follow **coordinated disclosure**:

1. **Receipt & acknowledgement** — we confirm receipt within the response SLA and open a
   private GitHub Security Advisory to coordinate.
2. **Triage** — we validate, reproduce, assign severity, and (for confirmed weaknesses)
   record an entry in the [POA&M](docs/compliance/POAM.md) so remediation is tracked.
3. **Embargo** — by default the issue stays **private (embargoed)** until a fix is
   available, up to a target of **90 days** from acknowledgement. We will request an
   extension if a complete fix needs longer, and we ask reporters to hold public
   disclosure until the embargo ends or a fix ships, whichever is first.
4. **Fix & release** — we develop the fix in private, validate it, and prepare a release
   and (where applicable) a published advisory with a CVE.
5. **Disclosure & credit** — once the fix is released, we publish the GitHub Security
   Advisory. With the reporter's consent, we credit them in the advisory. We do not offer
   a paid bug-bounty at this time.

If a vulnerability is being actively exploited in the wild, we may shorten the embargo and
expedite a fix and advisory.

## Vulnerability-management program

Coordinated disclosure is one input to the broader vulnerability-management program
(NIST **RA-5 / SI-2**, FedRAMP continuous monitoring), which is being established in
**phase P11** of the
[Production Readiness Plan](.omc/plans/PRODUCTION-READINESS-FEDRAMP-CIS.md). That program
adds automated, gating scanning (CodeQL, govulncheck, Trivy, gitleaks, Dependabot,
`pnpm audit`), a scheduled monthly authenticated scan, severity-to-SLA tracking, and
SLA-breach alerting. The detailed procedure (scan inventory, cadence, triage workflow,
false-positive/deviation register, and evidence retention) is documented in the
**vulnerability-management procedure** at `docs/security/vulnerability-management.md`
(P11 deliverable; this SECURITY.md is the authoritative source for the SLA figures the
procedure must match).

Open weaknesses for this disclosure/remediation program are tracked under
[POAM-025](docs/compliance/POAM.md) (scanning does not yet gate the build),
[POAM-026](docs/compliance/POAM.md) (no flaw-remediation program / SLAs), and
[POAM-033](docs/compliance/POAM.md) (supply-chain governance, including this SECURITY.md).

## Related documents

- [Plan of Action & Milestones (POA&M)](docs/compliance/POAM.md) — open security weaknesses and remediation plan.
- [Control matrix](docs/compliance/control-matrix.csv) — NIST 800-53 Rev 5 control implementation status.
- [System Security Plan](docs/compliance/ssp/SSP.md) — system description and control narratives.
- [System facts sheet](docs/compliance/system-facts.md) — authoritative component, port, and trust-zone IDs.
- [Production Readiness Plan](.omc/plans/PRODUCTION-READINESS-FEDRAMP-CIS.md) — phased remediation (P0–P12).
- [Vulnerability Management Procedure](docs/security/vulnerability-management.md) — scan inventory, cadence, triage workflow, suppression registers, and evidence retention (NIST RA-5, SI-2, SI-4, SI-5, CA-5).
