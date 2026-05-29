#!/usr/bin/env python3
"""Generator for the FedRAMP-Moderate control matrix (CSV).

Single source of truth for docs/compliance/control-matrix.csv. The control set is
the NIST SP 800-53 Rev 5 FedRAMP MODERATE baseline (base controls + Moderate
enhancements) across families AC AT AU CA CM CP IA IR MA MP PE PL PS RA SA SC SI
SR plus PM program controls.

Status/responsible-party are seeded from the grounded gap analysis
(.omc/research/fedramp-cis-gap-analysis.json) and the system facts sheet
(docs/compliance/system-facts.md). Remediating phases P0..P12 come from
.omc/plans/PRODUCTION-READINESS-FEDRAMP-CIS.md via the coverageMatrix
family->phase mapping.

Rules enforced by build():
  * NO blank status or responsible_party cell.
  * status in {Implemented,Partial,Planned,Inherited,Customer,Not-Applicable}.
  * one row per Moderate control.
"""
import csv

# Family -> primary remediating phase (first/anchor phase from coverageMatrix).
FAMILY_PHASE = {
    "AC": "P3", "AT": "P12", "AU": "P7", "CA": "P0", "CM": "P5", "CP": "P8",
    "IA": "P3", "IR": "P9", "MA": "P12", "MP": "P12", "PE": "P12", "PL": "P0",
    "PS": "P12", "RA": "P5", "SA": "P11", "SC": "P4", "SI": "P9", "SR": "P6",
    "PM": "P12",
}
FAMILY_NAME = {
    "AC": "Access Control", "AT": "Awareness and Training",
    "AU": "Audit and Accountability",
    "CA": "Assessment, Authorization, and Monitoring",
    "CM": "Configuration Management", "CP": "Contingency Planning",
    "IA": "Identification and Authentication", "IR": "Incident Response",
    "MA": "Maintenance", "MP": "Media Protection",
    "PE": "Physical and Environmental Protection", "PL": "Planning",
    "PS": "Personnel Security", "RA": "Risk Assessment",
    "SA": "System and Services Acquisition",
    "SC": "System and Communications Protection",
    "SI": "System and Information Integrity",
    "SR": "Supply Chain Risk Management", "PM": "Program Management",
}

# Default per-family responsible party for the procedural/program controls.
# Technical/system controls override per row below.
FAMILY_RP = {
    "AC": "System", "AT": "CSP", "AU": "System", "CA": "CSP", "CM": "System",
    "CP": "Shared", "IA": "System", "IR": "CSP", "MA": "Shared", "MP": "Shared",
    "PE": "Customer", "PL": "CSP", "PS": "CSP", "RA": "CSP", "SA": "System",
    "SC": "System", "SI": "System", "SR": "System", "PM": "CSP",
}

# Per-family default implementing artifact pointer when no specific repo path.
def see_phase(fam):
    return f"see {FAMILY_PHASE[fam]}"

# rows: list of (control_id, title, status, responsible_party,
#                implementing_artifact, remediating_phase_override_or_None,
#                poam_id, notes)
# When override phase is None the family default phase is used.
R = []

def add(cid, title, status, rp=None, art=None, phase=None, poam="", notes=""):
    R.append((cid, title, status, rp, art, phase, poam, notes))


# ---------------------------------------------------------------------------
# AC - Access Control
# ---------------------------------------------------------------------------
add("AC-1", "Policy and Procedures", "Planned", "CSP", "see P12", "P12", "POAM-010",
    "Access-control -1 policy not yet authored; drafted at SSP finalization.")
add("AC-2", "Account Management", "Planned", "System", "see P3", "P3", "POAM-001",
    "No app-plane account model; OIDC principals + lifecycle defined in P3.")
add("AC-2(1)", "Account Management | Automated System Account Management", "Planned",
    "System", "see P3", "P3", "POAM-001", "Automated account mgmt depends on P3 IdP integration.")
add("AC-2(2)", "Account Management | Automated Temporary and Emergency Account Management",
    "Planned", "System", "see P3", "P3", "", "Temporary/emergency account expiry handled by inherited IdP + P3.")
add("AC-2(3)", "Account Management | Disable Accounts", "Planned", "System", "see P3", "P3", "",
    "Account disablement via IdP; integrated in P3.")
add("AC-2(4)", "Account Management | Automated Audit Actions", "Planned", "System", "see P3", "P3", "",
    "Account-mgmt audit events depend on P3 authn + P7 audit pipeline.")
add("AC-2(5)", "Account Management | Inactivity Logout", "Planned", "System", "see P3", "P3", "",
    "Session inactivity logout to be enforced by dashboard OIDC session (P3).")
add("AC-2(12)", "Account Management | Account Monitoring for Atypical Usage", "Planned",
    "Shared", "see P9", "P9", "", "Atypical-usage detection via SIEM/alerting in P9.")
add("AC-2(13)", "Account Management | Disable Accounts for High-Risk Individuals", "Planned",
    "CSP", "see P12", "P12", "", "Procedural; depends on CSP HR/IdP process.")
add("AC-3", "Access Enforcement", "Planned", "System", "see P3", "P3", "POAM-001",
    "Data-plane unauthenticated today; authZ middleware + RBAC least-priv in P3.")
add("AC-4", "Information Flow Enforcement", "Planned", "System",
    "charts/kube-policies/templates/ (NetworkPolicy, P4)", "P4", "POAM-004",
    "No NetworkPolicy exists; default-deny + scoped flows in P4.")
add("AC-5", "Separation of Duties", "Planned", "System", "see P3", "P3", "",
    "Role separation defined alongside RBAC split in P3.")
add("AC-6", "Least Privilege", "Partial", "System", "charts/kube-policies/templates/rbac.yaml", "P3",
    "POAM-001", "Bright spot: pods runAsNonRoot/drop-ALL caps; SA RBAC still over-broad/shared (P3).")
add("AC-6(1)", "Least Privilege | Authorize Access to Security Functions", "Planned",
    "System", "charts/kube-policies/templates/rbac.yaml", "P3", "", "Security-function authZ refined in P3 RBAC split.")
add("AC-6(2)", "Least Privilege | Non-Privileged Access for Nonsecurity Functions", "Partial",
    "System", "charts/kube-policies/values.yaml", "P5", "",
    "Bright spot: containers run non-root, no privilege escalation; formalized in P5.")
add("AC-6(5)", "Least Privilege | Privileged Accounts", "Planned", "System", "see P3", "P3", "",
    "Privileged-account restriction handled by RBAC least-priv in P3.")
add("AC-6(7)", "Least Privilege | Review of User Privileges", "Planned", "CSP", "see P12", "P12", "",
    "Periodic privilege review is a procedural control (P12).")
add("AC-6(9)", "Least Privilege | Log Use of Privileged Functions", "Planned", "System", "see P7", "P7", "",
    "Privileged-function logging depends on P3 authn + P7 audit.")
add("AC-6(10)", "Least Privilege | Prohibit Non-Privileged Users from Executing Privileged Functions",
    "Planned", "System", "see P3", "P3", "", "Enforced via authZ middleware in P3.")
add("AC-7", "Unsuccessful Logon Attempts", "Inherited", "Customer", "Inherited from IdP/CSP", "P3", "",
    "Lockout thresholds inherited from federated IdP; verified in P3.")
add("AC-8", "System Use Notification", "Planned", "System", "see P3", "P3", "",
    "Login banner to be added to dashboard OIDC login (P3).")
add("AC-11", "Device Lock", "Inherited", "Customer", "Inherited from operator endpoints", "P12", "",
    "Endpoint/device lock is an operator-workstation control; inherited.")
add("AC-11(1)", "Device Lock | Pattern-Hiding Displays", "Inherited", "Customer",
    "Inherited from operator endpoints", "P12", "", "Endpoint control; inherited.")
add("AC-12", "Session Termination", "Planned", "System", "see P3", "P3", "",
    "Automatic session termination via dashboard OIDC session mgmt (P3).")
add("AC-14", "Permitted Actions Without Identification or Authentication", "Planned",
    "System", "cmd/dashboard/proxy.go", "P3", "",
    "Define unauthenticated-allowed actions (healthz/readyz); rest gated in P3.")
add("AC-17", "Remote Access", "Planned", "System", "see P3", "P3", "POAM-003",
    "Dashboard/API reachable without TLS+authn today; remote-access protection in P3.")
add("AC-17(1)", "Remote Access | Monitoring and Control", "Planned", "Shared", "see P9", "P9", "",
    "Remote-access monitoring via ConMon/SIEM in P9.")
add("AC-17(2)", "Remote Access | Protection of Confidentiality and Integrity Using Encryption",
    "Planned", "System", "see P3", "P3", "POAM-003",
    "TLS termination for management plane added in P3.")
add("AC-17(3)", "Remote Access | Managed Access Control Points", "Planned", "Shared",
    "see P4", "P4", "", "Managed access points via ingress + NetworkPolicy in P4.")
add("AC-17(4)", "Remote Access | Privileged Commands and Access", "Planned", "System", "see P3", "P3", "",
    "Privileged remote commands gated by authZ in P3.")
add("AC-18", "Wireless Access", "Not-Applicable", "Customer", "N/A - no wireless in boundary", None, "",
    "System has no wireless components; inherited infra control.")
add("AC-18(1)", "Wireless Access | Authentication and Encryption", "Not-Applicable", "Customer",
    "N/A - no wireless in boundary", None, "", "No wireless components in boundary.")
add("AC-19", "Access Control for Mobile Devices", "Inherited", "Customer",
    "Inherited from CSP/operator MDM", "P12", "", "Mobile-device control inherited from operator org.")
add("AC-20", "Use of External Systems", "Planned", "CSP", "see P12", "P12", "",
    "External-system rules of behavior authored in P12.")
add("AC-20(1)", "Use of External Systems | Limits on Authorized Use", "Planned", "CSP", "see P12", "P12", "",
    "Procedural; authored in P12.")
add("AC-20(2)", "Use of External Systems | Portable Storage Devices - Restricted Use", "Planned",
    "CSP", "see P12", "P12", "", "Procedural; authored in P12.")
add("AC-21", "Information Sharing", "Planned", "CSP", "see P12", "P12", "", "Procedural; authored in P12.")
add("AC-22", "Publicly Accessible Content", "Not-Applicable", "System", "N/A - no public content service", None, "",
    "System publishes no public-facing content; admin-only planes.")

# ---------------------------------------------------------------------------
# AT - Awareness and Training (program/CSP)
# ---------------------------------------------------------------------------
add("AT-1", "Policy and Procedures", "Planned", "CSP", "see P12", "P12", "POAM-010", "AT -1 policy authored in P12.")
add("AT-2", "Literacy Training and Awareness", "Planned", "CSP", "see P12", "P12", "", "Org security-awareness program (P12).")
add("AT-2(2)", "Literacy Training and Awareness | Insider Threat", "Planned", "CSP", "see P12", "P12", "",
    "Insider-threat awareness module (P12).")
add("AT-2(3)", "Literacy Training and Awareness | Social Engineering and Mining", "Planned", "CSP",
    "see P12", "P12", "", "Social-engineering awareness module (P12).")
add("AT-3", "Role-Based Training", "Planned", "CSP", "see P12", "P12", "", "Role-based training for ISSO/admins (P12).")
add("AT-4", "Training Records", "Planned", "CSP", "see P12", "P12", "", "Training-record retention (P12).")

# ---------------------------------------------------------------------------
# AU - Audit and Accountability
# ---------------------------------------------------------------------------
add("AU-1", "Policy and Procedures", "Planned", "CSP", "see P12", "P12", "POAM-010", "AU -1 policy authored in P12.")
add("AU-2", "Event Logging", "Partial", "System", "internal/audit/logger.go", "P7", "POAM-002",
    "Bright spot: webhook logs every allow/deny decision; mgmt-plane events + event-list completeness in P7.")
add("AU-3", "Content of Audit Records", "Partial", "System", "internal/audit/logger.go", "P7", "POAM-002",
    "Event struct captures who/what/when/decision; missing src IP/UA/req-URI added in P7.")
add("AU-3(1)", "Content of Audit Records | Additional Audit Information", "Planned", "System",
    "internal/audit/logger.go", "P7", "POAM-002", "Add source IP, user-agent, request-URI, apiserver-id in P7.")
add("AU-4", "Audit Log Storage Capacity", "Planned", "System",
    "charts/kube-policies/templates/policy-manager-pvc.yaml", "P7", "POAM-002",
    "Audit currently on emptyDir; durable PVC + capacity sizing in P7.")
add("AU-5", "Response to Audit Logging Process Failures", "Planned", "System", "see P7", "P7", "",
    "Audit-failure alerting wired in P7/P9.")
add("AU-6", "Audit Record Review, Analysis, and Reporting", "Planned", "Shared", "see P9", "P9", "",
    "Central review/SIEM analysis stood up in P9.")
add("AU-6(1)", "Audit Record Review | Automated Process Integration", "Planned", "Shared", "see P9", "P9", "",
    "Automated SIEM correlation in P9.")
add("AU-6(3)", "Audit Record Review | Correlate Audit Record Repositories", "Planned", "Shared", "see P9", "P9", "",
    "Cross-repository correlation in P9.")
add("AU-7", "Audit Record Reduction and Report Generation", "Planned", "Shared", "see P9", "P9", "",
    "Reduction/reporting provided by SIEM in P9.")
add("AU-7(1)", "Audit Record Reduction | Automatic Processing", "Planned", "Shared", "see P9", "P9", "",
    "Automatic query/processing in SIEM (P9).")
add("AU-8", "Time Stamps", "Partial", "System", "internal/audit/logger.go", "P7", "",
    "Records carry timestamps; dual-UTC + authoritative time source formalized in P7.")
add("AU-9", "Protection of Audit Information", "Planned", "System", "internal/audit/logger.go", "P7", "POAM-002",
    "No tamper protection today; HMAC signing + access restriction in P7.")
add("AU-9(2)", "Protection of Audit Information | Store on Separate Physical Systems or Components",
    "Planned", "Shared", "see P7", "P7", "", "Forwarding to separate SIEM store in P7/P9.")
add("AU-9(3)", "Protection of Audit Information | Cryptographic Protection", "Planned", "System",
    "internal/audit/logger.go", "P7", "POAM-002", "HMAC chain over audit records added in P7.")
add("AU-9(4)", "Protection of Audit Information | Access by Subset of Privileged Users", "Planned",
    "System", "see P7", "P7", "", "Restrict audit access to ISSO subset; RBAC in P3/P7.")
add("AU-11", "Audit Record Retention", "Planned", "Shared", "see P7", "P7", "",
    "Retention policy (FedRAMP) set in P7; long-term in SIEM (P9).")
add("AU-12", "Audit Record Generation", "Partial", "System", "internal/admission/controller.go", "P7", "",
    "Webhook generates decision records; mgmt-plane API audit generation added in P7.")
add("AU-12(1)", "Audit Record Generation | System-Wide and Time-Correlated Audit Trail", "Planned",
    "System", "see P7", "P7", "", "System-wide correlated trail across components in P7/P9.")

# ---------------------------------------------------------------------------
# CA - Assessment, Authorization, and Monitoring
# ---------------------------------------------------------------------------
add("CA-1", "Policy and Procedures", "Planned", "CSP", "see P12", "P12", "POAM-010", "CA -1 policy authored in P12.")
add("CA-2", "Control Assessments", "Planned", "CSP", "see P12", "P12", "", "Independent assessment scheduled in P12.")
add("CA-2(1)", "Control Assessments | Independent Assessors", "Planned", "CSP", "see P12", "P12", "",
    "Independent Assessor (TBD - assign) engaged in P12.")
add("CA-2(2)", "Control Assessments | Specialized Assessments", "Planned", "CSP", "see P12", "P12", "",
    "Pen test + specialized assessment in P12.")
add("CA-2(3)", "Control Assessments | Leveraging Results from External Organizations", "Planned",
    "CSP", "see P12", "P12", "", "Leverage CSP/3PAO results in P12.")
add("CA-3", "Information Exchange", "Planned", "System", "docs/compliance/system-facts.md (ICX-01..06)", "P4", "",
    "Interconnections ICX-01..06 documented; agreements + scoped flows in P4.")
add("CA-5", "Plan of Action and Milestones", "Partial", "CSP", "docs/compliance/poam.csv", "P0", "",
    "POA&M established (poam.csv); driven to closure across P1-P12.")
add("CA-6", "Authorization", "Planned", "CSP", "see P12", "P12", "", "AO (TBD - assign) authorization decision in P12.")
add("CA-7", "Continuous Monitoring", "Planned", "Shared", "see P9", "P9", "", "ConMon program stood up in P9.")
add("CA-7(1)", "Continuous Monitoring | Independent Assessment", "Planned", "CSP", "see P12", "P12", "",
    "Independent ConMon assessment in P12.")
add("CA-7(4)", "Continuous Monitoring | Risk Monitoring", "Planned", "Shared", "see P9", "P9", "",
    "Risk monitoring integrated with ConMon (P9).")
add("CA-8", "Penetration Testing", "Planned", "CSP", "see P12", "P12", "", "Independent pen test in P12.")
add("CA-9", "Internal System Connections", "Planned", "System", "docs/compliance/system-facts.md (ICX-02,04,06)", "P4", "",
    "Internal connections (ICX-02/04/06) documented; mTLS/TLS in P4.")

# ---------------------------------------------------------------------------
# CM - Configuration Management
# ---------------------------------------------------------------------------
add("CM-1", "Policy and Procedures", "Planned", "CSP", "see P12", "P12", "POAM-010", "CM -1 policy authored in P12.")
add("CM-2", "Baseline Configuration", "Partial", "System", "charts/kube-policies/values.yaml", "P5", "",
    "Secure-config baseline exists (TLS1.3, fail-closed defaults); formalized + versioned in P5.")
add("CM-2(2)", "Baseline Configuration | Automation Support for Accuracy and Currency", "Planned",
    "System", "charts/kube-policies/", "P5", "", "Helm-rendered baseline + CI drift checks in P5.")
add("CM-2(3)", "Baseline Configuration | Retention of Previous Configurations", "Planned", "System",
    "git history", "P5", "", "Config retained in VCS; formalized in P5.")
add("CM-3", "Configuration Change Control", "Planned", "System", "see P11", "P11", "",
    "Change-control via PR review + CI gates in P11.")
add("CM-3(2)", "Configuration Change Control | Testing, Validation, and Documentation of Changes",
    "Planned", "System", "see P11", "P11", "", "Change testing via CI quality gates in P11.")
add("CM-4", "Impact Analyses", "Planned", "System", "see P11", "P11", "", "Security-impact analysis in PR process (P11).")
add("CM-5", "Access Restrictions for Change", "Planned", "System", "see P1", "P1", "",
    "Branch protection + CODEOWNERS + signed commits in P1.")
add("CM-6", "Configuration Settings", "Partial", "System", "internal/config/config.go", "P5", "",
    "Config validation enforces TLS1.3/failure-mode; full CIS-restricted settings in P5.")
add("CM-6(1)", "Configuration Settings | Automated Management, Application, and Verification", "Planned",
    "System", "charts/kube-policies/", "P5", "", "CI renders + verifies settings (helm template gate) in P5.")
add("CM-7", "Least Functionality", "Partial", "System", "charts/kube-policies/values.yaml", "P5", "",
    "Distroless images, dropped caps; restricted PSS + disabled services in P5.")
add("CM-7(1)", "Least Functionality | Periodic Review", "Planned", "System", "see P5", "P5", "",
    "Periodic review of enabled functions in P5/P11.")
add("CM-7(2)", "Least Functionality | Prevent Program Execution", "Planned", "System",
    "internal/policy/engine.go", "P10", "", "Image/exec policy enforcement extended in P10.")
add("CM-7(5)", "Least Functionality | Authorized Software - Allow-by-Exception", "Planned", "System",
    "see P6", "P6", "", "Image-signature/allowlist admission in P6/P10.")
add("CM-8", "System Component Inventory", "Partial", "System", "docs/compliance/inventory.csv", "P0", "",
    "Inventory established (AST-* assets); kept current per release in P5/P6.")
add("CM-8(1)", "System Component Inventory | Updates During Installation and Removal", "Planned",
    "System", "docs/compliance/inventory.csv", "P6", "", "Inventory auto-updated from SBOM in P6.")
add("CM-8(3)", "System Component Inventory | Automated Unauthorized Component Detection", "Planned",
    "System", "see P6", "P6", "", "SBOM/scan-driven detection in P6.")
add("CM-9", "Configuration Management Plan", "Planned", "CSP", "see P12", "P12", "", "CM plan authored in P12.")
add("CM-10", "Software Usage Restrictions", "Planned", "CSP", "see P12", "P12", "", "Software-usage policy in P12.")
add("CM-11", "User-Installed Software", "Planned", "System", "charts/kube-policies/values.yaml", "P5", "",
    "Immutable distroless images + readOnlyRootFilesystem restrict installs; formalized P5.")
add("CM-12", "Information Location", "Planned", "System", "docs/compliance/system-facts.md", "P0", "",
    "Information types IT-1..3 located in CRDs/audit; documented in facts sheet, finalized P12.")
add("CM-14", "Signed Components", "Planned", "System", "see P6", "P6", "POAM-006",
    "Cosign signing + signature-verifying admission in P6.")

# ---------------------------------------------------------------------------
# CP - Contingency Planning
# ---------------------------------------------------------------------------
add("CP-1", "Policy and Procedures", "Planned", "CSP", "see P12", "P12", "POAM-010", "CP -1 policy authored in P12.")
add("CP-2", "Contingency Plan", "Planned", "Shared", "see P8", "P8", "", "Contingency plan authored in P8/P12.")
add("CP-2(1)", "Contingency Plan | Coordinate with Related Plans", "Planned", "CSP", "see P12", "P12", "",
    "Coordinate with IR/CSP DR plans in P12.")
add("CP-2(3)", "Contingency Plan | Resume Mission and Business Functions", "Planned", "Shared", "see P8", "P8", "",
    "Resumption objectives defined in P8.")
add("CP-2(8)", "Contingency Plan | Identify Critical Assets", "Partial", "System", "docs/compliance/inventory.csv", "P8", "",
    "Critical assets (AST-WH gatekeeper) identified in inventory; RTO/RPO in P8.")
add("CP-3", "Contingency Training", "Planned", "CSP", "see P12", "P12", "", "Contingency training in P12.")
add("CP-4", "Contingency Plan Testing", "Planned", "Shared", "see P8", "P8", "", "DR/restore testing in P8.")
add("CP-4(1)", "Contingency Plan Testing | Coordinate with Related Plans", "Planned", "CSP", "see P12", "P12", "",
    "Coordinated test with CSP plans in P12.")
add("CP-6", "Alternate Storage Site", "Inherited", "Customer", "Inherited from CSP infrastructure", "P8", "",
    "Alternate storage inherited from hosting CSP; backup targets defined in P8.")
add("CP-6(1)", "Alternate Storage Site | Separation from Primary Site", "Inherited", "Customer",
    "Inherited from CSP infrastructure", "P8", "", "Geographic separation inherited from CSP.")
add("CP-6(3)", "Alternate Storage Site | Accessibility", "Inherited", "Customer", "Inherited from CSP infrastructure", "P8", "",
    "Accessibility inherited from CSP.")
add("CP-7", "Alternate Processing Site", "Inherited", "Customer", "Inherited from CSP infrastructure", "P8", "",
    "Alternate processing inherited from CSP region/cluster topology.")
add("CP-7(1)", "Alternate Processing Site | Separation from Primary Site", "Inherited", "Customer",
    "Inherited from CSP infrastructure", "P8", "", "Separation inherited from CSP.")
add("CP-7(2)", "Alternate Processing Site | Accessibility", "Inherited", "Customer", "Inherited from CSP infrastructure", "P8", "",
    "Accessibility inherited from CSP.")
add("CP-7(3)", "Alternate Processing Site | Priority of Service", "Inherited", "Customer",
    "Inherited from CSP infrastructure", "P8", "", "Priority-of-service inherited from CSP.")
add("CP-8", "Telecommunications Services", "Inherited", "Customer", "Inherited from CSP infrastructure", "P8", "",
    "Telecom services inherited from hosting CSP.")
add("CP-8(1)", "Telecommunications Services | Priority of Service Provisions", "Inherited", "Customer",
    "Inherited from CSP infrastructure", "P8", "", "Inherited from CSP.")
add("CP-8(2)", "Telecommunications Services | Single Points of Failure", "Inherited", "Customer",
    "Inherited from CSP infrastructure", "P8", "", "Inherited from CSP.")
add("CP-9", "System Backup", "Planned", "Shared", "charts/kube-policies/templates/policy-manager-pvc.yaml", "P8", "POAM-007",
    "CRDs in etcd (CSP-backed); app-state/audit backup procedure defined in P8.")
add("CP-9(1)", "System Backup | Testing for Reliability and Integrity", "Planned", "Shared", "see P8", "P8", "POAM-007",
    "Backup-restore reliability testing in P8.")
add("CP-10", "System Recovery and Reconstitution", "Partial", "System", "cmd/admission-webhook/main.go (leader election)", "P8", "",
    "Leader election + replicas aid recovery; full reconstitution/RTO-RPO in P8.")
add("CP-10(2)", "System Recovery and Reconstitution | Transaction Recovery", "Planned", "System", "see P8", "P8", "",
    "Decision/transaction recovery semantics defined in P8.")

# ---------------------------------------------------------------------------
# IA - Identification and Authentication
# ---------------------------------------------------------------------------
add("IA-1", "Policy and Procedures", "Planned", "CSP", "see P12", "P12", "POAM-010", "IA -1 policy authored in P12.")
add("IA-2", "Identification and Authentication (Organizational Users)", "Planned", "System", "see P3", "P3", "POAM-001",
    "No user authn on planes today; OIDC bearer auth on every /api/v1 route in P3.")
add("IA-2(1)", "IA (Organizational Users) | MFA to Privileged Accounts", "Planned", "Shared", "see P3", "P3", "",
    "MFA enforced by federated IdP; integrated in P3.")
add("IA-2(2)", "IA (Organizational Users) | MFA to Non-Privileged Accounts", "Planned", "Shared", "see P3", "P3", "",
    "MFA via federated IdP; integrated in P3.")
add("IA-2(8)", "IA (Organizational Users) | Access to Accounts - Replay Resistant", "Planned", "System", "see P3", "P3", "",
    "Replay-resistant OIDC tokens (nonce/aud) verified in P3.")
add("IA-2(12)", "IA (Organizational Users) | Acceptance of PIV Credentials", "Planned", "Shared", "see P3", "P3", "",
    "PIV acceptance via IdP federation; verified in P3.")
add("IA-3", "Device Identification and Authentication", "Planned", "System", "charts/kube-policies/templates/admission-webhook-tls.yaml", "P3", "POAM-003",
    "mTLS to apiserver + audience-bound service tokens (ICX-01/02) in P3.")
add("IA-4", "Identifier Management", "Planned", "Shared", "see P3", "P3", "", "Identifier mgmt via IdP; service identities in P3.")
add("IA-5", "Authenticator Management", "Planned", "System", "see P2", "P2", "POAM-003",
    "Static bearer token today; cert/secret lifecycle + rotation in P2.")
add("IA-5(1)", "Authenticator Management | Password-Based Authentication", "Inherited", "Customer", "Inherited from IdP", "P3", "",
    "Password policy inherited from federated IdP.")
add("IA-5(2)", "Authenticator Management | Public Key-Based Authentication", "Planned", "System", "see P2", "P2", "",
    "PKI cert lifecycle (webhook/mTLS certs) in P2.")
add("IA-6", "Authentication Feedback", "Inherited", "Customer", "Inherited from IdP", "P3", "",
    "Authn feedback obscuring inherited from IdP login UI.")
add("IA-7", "Cryptographic Module Authentication", "Planned", "System", "see P2", "P2", "POAM-005",
    "FIPS-140-3 validated module (GOFIPS140) established in P2.")
add("IA-8", "Identification and Authentication (Non-Organizational Users)", "Planned", "System", "see P3", "P3", "",
    "Non-org user authn scoping in P3 (likely N/A post-scoping).")
add("IA-8(1)", "IA (Non-Org Users) | Acceptance of PIV Credentials from Other Agencies", "Planned", "Shared", "see P3", "P3", "",
    "PIV-I acceptance via IdP federation (P3).")
add("IA-8(2)", "IA (Non-Org Users) | Acceptance of External Authenticators", "Planned", "Shared", "see P3", "P3", "",
    "External authenticator acceptance via IdP (P3).")
add("IA-8(4)", "IA (Non-Org Users) | Use of Defined Profiles", "Planned", "Shared", "see P3", "P3", "",
    "Identity-profile conformance via IdP (P3).")
add("IA-11", "Re-Authentication", "Planned", "System", "see P3", "P3", "", "Re-authentication on privileged actions/session expiry in P3.")
add("IA-12", "Identity Proofing", "Inherited", "Customer", "Inherited from IdP/CSP", "P3", "", "Identity proofing inherited from federated IdP.")
add("IA-12(2)", "Identity Proofing | Identity Evidence", "Inherited", "Customer", "Inherited from IdP/CSP", "P3", "",
    "Identity evidence handling inherited from IdP.")
add("IA-12(3)", "Identity Proofing | Identity Evidence Validation and Verification", "Inherited", "Customer",
    "Inherited from IdP/CSP", "P3", "", "Evidence validation inherited from IdP.")
add("IA-12(5)", "Identity Proofing | Address Confirmation", "Inherited", "Customer", "Inherited from IdP/CSP", "P3", "",
    "Address confirmation inherited from IdP.")

# ---------------------------------------------------------------------------
# IR - Incident Response
# ---------------------------------------------------------------------------
add("IR-1", "Policy and Procedures", "Planned", "CSP", "see P12", "P12", "POAM-010", "IR -1 policy authored in P12.")
add("IR-2", "Incident Response Training", "Planned", "CSP", "see P12", "P12", "", "IR training program in P12.")
add("IR-3", "Incident Response Testing", "Planned", "CSP", "see P9", "P9", "", "Tabletop/IR testing scheduled in P9/P12.")
add("IR-3(2)", "Incident Response Testing | Coordination with Related Plans", "Planned", "CSP", "see P12", "P12", "",
    "Coordinated with CP/CSP plans in P12.")
add("IR-4", "Incident Handling", "Planned", "Shared", "see P9", "P9", "", "Incident-handling workflow from alerting in P9.")
add("IR-4(1)", "Incident Handling | Automated Incident Handling Processes", "Planned", "Shared", "see P9", "P9", "",
    "Automated alert-to-incident pipeline in P9.")
add("IR-5", "Incident Monitoring", "Planned", "Shared", "see P9", "P9", "", "Incident monitoring via metrics/alerts in P9.")
add("IR-6", "Incident Reporting", "Planned", "CSP", "see P9", "P9", "", "US-CERT/CSP reporting workflow in P9/P12.")
add("IR-6(1)", "Incident Reporting | Automated Reporting", "Planned", "Shared", "see P9", "P9", "",
    "Automated reporting integration in P9.")
add("IR-7", "Incident Response Assistance", "Planned", "CSP", "see P12", "P12", "", "IR assistance/contacts defined in P12.")
add("IR-7(1)", "Incident Response Assistance | Automation Support for Availability of Information", "Planned",
    "Shared", "see P9", "P9", "", "Automation support via SIEM/runbooks in P9.")
add("IR-8", "Incident Response Plan", "Planned", "CSP", "see P12", "P12", "POAM-010", "IR plan authored in P12.")

# ---------------------------------------------------------------------------
# MA - Maintenance
# ---------------------------------------------------------------------------
add("MA-1", "Policy and Procedures", "Planned", "CSP", "see P12", "P12", "POAM-010", "MA -1 policy authored in P12.")
add("MA-2", "Controlled Maintenance", "Planned", "Shared", "see P12", "P12", "", "Maintenance via GitOps/rolling upgrade; procedure in P12.")
add("MA-3", "Maintenance Tools", "Inherited", "Customer", "Inherited from CSP", "P12", "", "Physical maintenance tools inherited from CSP.")
add("MA-3(1)", "Maintenance Tools | Inspect Tools", "Inherited", "Customer", "Inherited from CSP", "P12", "",
    "Tool inspection inherited from CSP.")
add("MA-3(2)", "Maintenance Tools | Inspect Media", "Inherited", "Customer", "Inherited from CSP", "P12", "",
    "Media inspection inherited from CSP.")
add("MA-3(3)", "Maintenance Tools | Prevent Unauthorized Removal", "Inherited", "Customer", "Inherited from CSP", "P12", "",
    "Inherited from CSP.")
add("MA-4", "Nonlocal Maintenance", "Planned", "Shared", "see P3", "P3", "", "Remote maintenance over authenticated/TLS planes (P3); procedure P12.")
add("MA-5", "Maintenance Personnel", "Inherited", "Customer", "Inherited from CSP", "P12", "", "Maintenance-personnel vetting inherited from CSP/operator.")
add("MA-6", "Timely Maintenance", "Planned", "Shared", "see P12", "P12", "", "Spares/support-availability via container orchestration; procedure P12.")

# ---------------------------------------------------------------------------
# MP - Media Protection (physical/environmental largely inherited)
# ---------------------------------------------------------------------------
add("MP-1", "Policy and Procedures", "Planned", "CSP", "see P12", "P12", "POAM-010", "MP -1 policy authored in P12.")
add("MP-2", "Media Access", "Inherited", "Customer", "Inherited from CSP", "P12", "", "Physical media access inherited from CSP.")
add("MP-3", "Media Marking", "Inherited", "Customer", "Inherited from CSP", "P12", "", "Media marking inherited from CSP.")
add("MP-4", "Media Storage", "Inherited", "Customer", "Inherited from CSP", "P12", "", "Physical media storage inherited from CSP.")
add("MP-5", "Media Transport", "Inherited", "Customer", "Inherited from CSP", "P12", "", "Media transport inherited from CSP.")
add("MP-6", "Media Sanitization", "Inherited", "Customer", "Inherited from CSP", "P12", "", "Media sanitization inherited from CSP.")
add("MP-7", "Media Use", "Planned", "CSP", "see P12", "P12", "", "Removable-media use policy authored in P12.")

# ---------------------------------------------------------------------------
# PE - Physical and Environmental Protection (all inherited from CSP)
# ---------------------------------------------------------------------------
PE = [
    ("PE-1", "Policy and Procedures"),
    ("PE-2", "Physical Access Authorizations"),
    ("PE-3", "Physical Access Control"),
    ("PE-4", "Access Control for Transmission"),
    ("PE-5", "Access Control for Output Devices"),
    ("PE-6", "Monitoring Physical Access"),
    ("PE-6(1)", "Monitoring Physical Access | Intrusion Alarms and Surveillance Equipment"),
    ("PE-8", "Visitor Access Records"),
    ("PE-9", "Power Equipment and Cabling"),
    ("PE-10", "Emergency Shutoff"),
    ("PE-11", "Emergency Power"),
    ("PE-12", "Emergency Lighting"),
    ("PE-13", "Fire Protection"),
    ("PE-13(1)", "Fire Protection | Detection Systems - Automatic Activation and Notification"),
    ("PE-13(2)", "Fire Protection | Suppression Systems - Automatic Activation and Notification"),
    ("PE-14", "Environmental Controls"),
    ("PE-15", "Water Damage Protection"),
    ("PE-16", "Delivery and Removal"),
    ("PE-17", "Alternate Work Site"),
]
for cid, title in PE:
    add(cid, title, "Inherited", "Customer", "Inherited from CSP data center", "P12", "",
        "Physical/environmental control fully inherited from hosting CSP; verified via CSP ATO/CRM in P12.")

# ---------------------------------------------------------------------------
# PL - Planning
# ---------------------------------------------------------------------------
add("PL-1", "Policy and Procedures", "Planned", "CSP", "see P12", "P12", "POAM-010", "PL -1 policy authored in P12.")
add("PL-2", "System Security and Privacy Plans", "Partial", "CSP", "docs/compliance/ssp/SSP.md", "P0", "",
    "SSP skeleton established in P0; narratives finalized in P12.")
add("PL-4", "Rules of Behavior", "Planned", "CSP", "see P12", "P12", "", "Rules of behavior authored in P12.")
add("PL-4(1)", "Rules of Behavior | Social Media and External Site/Application Usage Restrictions", "Planned",
    "CSP", "see P12", "P12", "", "Authored in P12.")
add("PL-8", "Security and Privacy Architectures", "Partial", "System", "docs/compliance/system-facts.md", "P0", "",
    "Architecture/trust-zones (ZONE-EXT/ZONE-SYS) documented in facts + boundary; finalized in SSP P12.")
add("PL-10", "Baseline Selection", "Implemented", "CSP", "docs/compliance/control-matrix.csv", "P0", "",
    "FedRAMP Moderate baseline selected (this matrix); reconcile vs official OSCAL profile - POAM-009.")
add("PL-11", "Baseline Tailoring", "Partial", "CSP", "docs/compliance/control-matrix.md", "P0", "POAM-009",
    "Tailoring (N/A, inherited) recorded here; reconcile vs official FedRAMP Rev5 Moderate OSCAL profile.")

# ---------------------------------------------------------------------------
# PS - Personnel Security
# ---------------------------------------------------------------------------
add("PS-1", "Policy and Procedures", "Planned", "CSP", "see P12", "P12", "POAM-010", "PS -1 policy authored in P12.")
add("PS-2", "Position Risk Designation", "Planned", "CSP", "see P12", "P12", "", "Position risk designation in P12.")
add("PS-3", "Personnel Screening", "Inherited", "Customer", "Inherited from CSP/operator HR", "P12", "",
    "Personnel screening inherited from operator org; verified P12.")
add("PS-4", "Personnel Termination", "Planned", "CSP", "see P12", "P12", "", "Termination/offboarding procedure in P12.")
add("PS-5", "Personnel Transfer", "Planned", "CSP", "see P12", "P12", "", "Transfer procedure in P12.")
add("PS-6", "Access Agreements", "Planned", "CSP", "see P12", "P12", "", "Access agreements in P12.")
add("PS-7", "External Personnel Security", "Planned", "CSP", "see P12", "P12", "", "External-personnel security in P12.")
add("PS-8", "Personnel Sanctions", "Planned", "CSP", "see P12", "P12", "", "Sanctions process in P12.")
add("PS-9", "Position Descriptions", "Planned", "CSP", "see P12", "P12", "", "Security position descriptions in P12.")

# ---------------------------------------------------------------------------
# RA - Risk Assessment
# ---------------------------------------------------------------------------
add("RA-1", "Policy and Procedures", "Planned", "CSP", "see P12", "P12", "POAM-010", "RA -1 policy authored in P12.")
add("RA-2", "Security Categorization", "Implemented", "CSP", "docs/compliance/categorization/FIPS-199.md", "P0", "",
    "FIPS-199 Moderate categorization completed in P0.")
add("RA-3", "Risk Assessment", "Partial", "CSP", ".omc/research/fedramp-cis-gap-analysis.json", "P0", "",
    "Grounded 12-dimension gap analysis serves as initial risk assessment; formal RA in P12.")
add("RA-3(1)", "Risk Assessment | Supply Chain Risk Assessment", "Planned", "System", "see P6", "P6", "",
    "Supply-chain risk assessment (SBOM/provenance) in P6.")
add("RA-5", "Vulnerability Monitoring and Scanning", "Partial", "System", ".github/workflows/ci.yml (trivy)", "P6", "POAM-008",
    "Trivy fs/image scan exists but non-gating; authenticated monthly gating scans + SLA in P6/P11.")
add("RA-5(2)", "Vulnerability Monitoring and Scanning | Update Vulnerabilities to Be Scanned", "Planned",
    "System", "see P6", "P6", "", "Scanner DB auto-update + cadence in P6/P11.")
add("RA-5(5)", "Vulnerability Monitoring and Scanning | Privileged Access", "Planned", "System", "see P11", "P11", "",
    "Authenticated/credentialed scanning configured in P11.")
add("RA-7", "Risk Response", "Partial", "CSP", "docs/compliance/poam.csv", "P0", "",
    "Risk response tracked via POA&M; closure across P1-P12.")

# ---------------------------------------------------------------------------
# SA - System and Services Acquisition
# ---------------------------------------------------------------------------
add("SA-1", "Policy and Procedures", "Planned", "CSP", "see P12", "P12", "POAM-010", "SA -1 policy authored in P12.")
add("SA-2", "Allocation of Resources", "Planned", "CSP", "see P12", "P12", "", "Resource allocation for security in P12.")
add("SA-3", "System Development Life Cycle", "Partial", "CSP", "CONTRIBUTING.md", "P11", "",
    "SDLC scaffold exists (CI, PR review); secure-SDLC formalized in P11.")
add("SA-4", "Acquisition Process", "Planned", "CSP", "see P12", "P12", "", "Acquisition/security-requirements language in P12.")
add("SA-4(1)", "Acquisition Process | Functional Properties of Controls", "Planned", "CSP", "see P12", "P12", "",
    "Functional-property requirements in P12.")
add("SA-4(2)", "Acquisition Process | Design and Implementation Information for Controls", "Planned", "CSP",
    "see P12", "P12", "", "Design/impl documentation in P12.")
add("SA-4(9)", "Acquisition Process | Functions, Ports, Protocols, and Services in Use", "Partial", "System",
    "docs/compliance/system-facts.md (ports table)", "P0", "",
    "Ports/protocols/services documented in facts sheet; finalized in SSP P12.")
add("SA-4(10)", "Acquisition Process | Use of Approved PIV Products", "Planned", "Shared", "see P3", "P3", "",
    "PIV product use via IdP federation (P3).")
add("SA-5", "System Documentation", "Partial", "System", "README.md", "P11", "",
    "Engineering docs exist; admin/security documentation completed in P11/P12.")
add("SA-8", "Security and Privacy Engineering Principles", "Partial", "System", "docs/compliance/system-facts.md", "P0", "",
    "Trust-zone/fail-closed design principles applied; documented across P0-P12.")
add("SA-9", "External System Services", "Planned", "CSP", "see P12", "P12", "", "External-service agreements (CSP/IdP) in P12.")
add("SA-9(2)", "External System Services | Identification of Functions, Ports, Protocols, and Services", "Partial",
    "System", "docs/compliance/system-facts.md (ICX-01..06)", "P4", "",
    "External connections ICX-01..06 enumerated; agreements in P12.")
add("SA-10", "Developer Configuration Management", "Partial", "System", ".github/workflows/release.yml", "P6", "",
    "Versioned build via CI/Helm; provenance/SBOM integrity in P6.")
add("SA-11", "Developer Testing and Evaluation", "Partial", "System", ".github/workflows/ci.yml", "P11", "",
    "Unit tests + trivy/scan exist (non-gating); enforced SAST/DAST/coverage gates in P11.")
add("SA-11(1)", "Developer Testing and Evaluation | Static Code Analysis", "Planned", "System", "see P11", "P11", "POAM-008",
    "CodeQL/gosec gating SAST added in P11.")
add("SA-11(8)", "Developer Testing and Evaluation | Dynamic Code Analysis", "Planned", "System", "see P11", "P11", "",
    "DAST/fuzz harness added in P11.")
add("SA-15", "Development Process, Standards, and Tools", "Partial", "System", "Makefile", "P11", "",
    "Toolchain/Make targets exist; documented secure dev process + tool baseline in P11.")
add("SA-15(3)", "Development Process | Criticality Analysis", "Planned", "System", "see P11", "P11", "",
    "Criticality analysis integrated in P11.")
add("SA-22", "Unsupported System Components", "Planned", "System", "see P1", "P1", "",
    "Go 1.25 toolchain alignment + EOL removal in P1; ongoing in P6/P11.")

# ---------------------------------------------------------------------------
# SC - System and Communications Protection
# ---------------------------------------------------------------------------
add("SC-1", "Policy and Procedures", "Planned", "CSP", "see P12", "P12", "POAM-010", "SC -1 policy authored in P12.")
add("SC-2", "Separation of System and User Functionality", "Partial", "System", "cmd/dashboard/proxy.go", "P3", "",
    "Dashboard BFF separates UI from API; management/enforcement plane split formalized in P3/P4.")
add("SC-4", "Information in Shared System Resources", "Planned", "System", "charts/kube-policies/values.yaml", "P5", "",
    "readOnlyRootFilesystem + non-root reduce residual data; formalized in P5.")
add("SC-5", "Denial-of-Service Protection", "Planned", "System", "see P4", "P4", "",
    "Rate limiting + resource limits + fail-closed posture in P4/P8.")
add("SC-6", "Resource Availability", "Partial", "System", "cmd/admission-webhook/main.go (leader election)", "P8", "",
    "Replicas + leader election aid availability; PDB/anti-affinity/limits in P8.")
add("SC-7", "Boundary Protection", "Planned", "System", "charts/kube-policies/templates/ (NetworkPolicy, P4)", "P4", "POAM-004",
    "No NetworkPolicy today; default-deny boundary + scoped flows in P4.")
add("SC-7(3)", "Boundary Protection | Access Points", "Planned", "System", "see P4", "P4", "POAM-004",
    "Limit/manage access points via ingress + NetworkPolicy in P4.")
add("SC-7(4)", "Boundary Protection | External Telecommunications Services", "Planned", "System", "see P4", "P4", "",
    "Scoped egress (DNS/apiserver only) + traffic agreements in P4.")
add("SC-7(5)", "Boundary Protection | Deny by Default - Allow by Exception", "Planned", "System",
    "charts/kube-policies/templates/ (NetworkPolicy, P4)", "P4", "POAM-004",
    "Default-deny ingress+egress NetworkPolicy with scoped allow in P4.")
add("SC-7(7)", "Boundary Protection | Split Tunneling for Remote Devices", "Planned", "System", "see P4", "P4", "",
    "Split-tunnel prevention via egress policy in P4.")
add("SC-8", "Transmission Confidentiality and Integrity", "Partial", "System", "cmd/admission-webhook/main.go:269-280", "P4", "POAM-003",
    "Bright spot: webhook serves TLS 1.3 with fixed cipher suites; other planes plaintext - TLS/mTLS in P3/P4.")
add("SC-8(1)", "Transmission Confidentiality and Integrity | Cryptographic Protection", "Partial", "System",
    "cmd/admission-webhook/main.go:269-280", "P4", "POAM-003",
    "Webhook TLS1.3 cryptographic protection present (ICX-01); in-cluster mTLS for ICX-02/04 in P4.")
add("SC-10", "Network Disconnect", "Planned", "System", "see P3", "P3", "", "Session/idle disconnect on management plane in P3.")
add("SC-12", "Cryptographic Key Establishment and Management", "Planned", "System", "charts/kube-policies/templates/admission-webhook-tls.yaml", "P2", "POAM-005",
    "Cert/secret material exists but no lifecycle; PKI key mgmt + rotation in P2.")
add("SC-12(2)", "Cryptographic Key Establishment | Symmetric Keys", "Planned", "System", "see P2", "P2", "",
    "Symmetric key mgmt (audit HMAC key) in P2.")
add("SC-12(3)", "Cryptographic Key Establishment | Asymmetric Keys", "Planned", "System", "see P2", "P2", "",
    "Asymmetric key mgmt (TLS/mTLS certs) in P2.")
add("SC-13", "Cryptographic Protection", "Planned", "System", "see P2", "P2", "POAM-005",
    "No FIPS-validated module today; FIPS-140-3 (GOFIPS140) crypto in P2.")
add("SC-15", "Collaborative Computing Devices and Applications", "Not-Applicable", "System", "N/A - no collaborative computing", None, "",
    "System has no collaborative-computing (mic/camera) components.")
add("SC-17", "Public Key Infrastructure Certificates", "Planned", "System", "see P2", "P2", "POAM-005",
    "PKI certificate issuance/management (cert-manager or equivalent) in P2.")
add("SC-18", "Mobile Code", "Planned", "System", "web/", "P5", "",
    "Svelte SPA mobile code; CSP headers + integrity controls in P5.")
add("SC-20", "Secure Name/Address Resolution Service (Authoritative Source)", "Inherited", "Customer",
    "Inherited from cluster DNS/CSP", "P4", "", "Authoritative DNS inherited from cluster/CSP; egress scoped in P4.")
add("SC-21", "Secure Name/Address Resolution Service (Recursive or Caching Resolver)", "Inherited", "Customer",
    "Inherited from cluster DNS/CSP", "P4", "", "Recursive resolver inherited from cluster CoreDNS/CSP.")
add("SC-22", "Architecture and Provisioning for Name/Address Resolution Service", "Inherited", "Customer",
    "Inherited from cluster DNS/CSP", "P4", "", "DNS architecture inherited from cluster/CSP.")
add("SC-23", "Session Authenticity", "Planned", "System", "see P3", "P3", "",
    "TLS session authenticity on all planes + token binding in P3.")
add("SC-28", "Protection of Information at Rest", "Planned", "System", "see P2", "P2", "POAM-005",
    "CRDs in etcd; etcd encryption-at-rest verification + app at-rest crypto in P2.")
add("SC-28(1)", "Protection of Information at Rest | Cryptographic Protection", "Planned", "Shared", "see P2", "P2", "POAM-005",
    "Encryption-at-rest via CSP/etcd KMS + FIPS module; verified in P2.")
add("SC-39", "Process Isolation", "Partial", "System", "charts/kube-policies/values.yaml", "P5", "",
    "Container isolation (distroless, non-root, dropped caps); restricted PSS in P5.")

# ---------------------------------------------------------------------------
# SI - System and Information Integrity
# ---------------------------------------------------------------------------
add("SI-1", "Policy and Procedures", "Planned", "CSP", "see P12", "P12", "POAM-010", "SI -1 policy authored in P12.")
add("SI-2", "Flaw Remediation", "Partial", "System", ".github/workflows/ci.yml", "P6", "POAM-008",
    "Scanning produces signal but no SLA/patch process; flaw-remediation cadence + gating in P6/P11.")
add("SI-2(2)", "Flaw Remediation | Automated Flaw Remediation Status", "Planned", "System", "see P6", "P6", "POAM-008",
    "Automated remediation-status tracking via scan + POA&M in P6/P11.")
add("SI-3", "Malicious Code Protection", "Planned", "System", "see P6", "P6", "",
    "Image scanning (trivy) + signature verification admission in P6/P10.")
add("SI-4", "System Monitoring", "Partial", "System", "internal/metrics/collector.go", "P9", "",
    "Prometheus collector + Alertmanager exist (PoC); IDS-grade detection/SIEM in P9.")
add("SI-4(2)", "System Monitoring | Automated Tools and Mechanisms for Real-Time Analysis", "Planned",
    "Shared", "see P9", "P9", "", "Real-time SIEM analysis in P9.")
add("SI-4(4)", "System Monitoring | Inbound and Outbound Communications Traffic", "Planned", "Shared", "see P9", "P9", "",
    "Traffic monitoring (NetworkPolicy logs + SIEM) in P4/P9.")
add("SI-4(5)", "System Monitoring | System-Generated Alerts", "Planned", "Shared", "internal/metrics/collector.go", "P9", "",
    "System-generated security alerts packaged as PrometheusRule in P9.")
add("SI-5", "Security Alerts, Advisories, and Directives", "Planned", "CSP", "see P11", "P11", "",
    "CISA/vendor advisory intake process in P11/P12.")
add("SI-6", "Security and Privacy Function Verification", "Planned", "System", "see P11", "P11", "",
    "Self-test/function verification of security controls in P11.")
add("SI-7", "Software, Firmware, and Information Integrity", "Planned", "System", "see P6", "P6", "POAM-006",
    "Image-signature verification + SBOM/provenance integrity in P6.")
add("SI-7(1)", "Software, Firmware, and Information Integrity | Integrity Checks", "Planned", "System", "see P6", "P6", "POAM-006",
    "Integrity checks at admission (cosign verify) in P6/P10.")
add("SI-8", "Spam Protection", "Not-Applicable", "System", "N/A - no email/messaging in boundary", None, "",
    "System has no email/messaging components.")
add("SI-10", "Information Input Validation", "Partial", "System", "internal/config/config.go", "P3", "",
    "Config + admission input validation present; API request validation hardened in P3/P11.")
add("SI-11", "Error Handling", "Partial", "System", "internal/policymanager/router.go", "P11", "",
    "gin.Recovery() handles panics; structured error handling/no-leak review in P11.")
add("SI-12", "Information Management and Retention", "Planned", "Shared", "see P7", "P7", "",
    "Audit/data retention policy defined in P7; long-term in P9.")
add("SI-16", "Memory Protection", "Partial", "System", "charts/kube-policies/values.yaml", "P5", "",
    "Go memory safety + non-root/read-only FS; seccomp RuntimeDefault in P5.")

# ---------------------------------------------------------------------------
# SR - Supply Chain Risk Management
# ---------------------------------------------------------------------------
add("SR-1", "Policy and Procedures", "Planned", "CSP", "see P12", "P12", "POAM-010", "SR -1 policy authored in P12.")
add("SR-2", "Supply Chain Risk Management Plan", "Planned", "CSP", "see P6", "P6", "", "SCRM plan authored in P6/P12.")
add("SR-2(1)", "Supply Chain Risk Management Plan | Establish SCRM Team", "Planned", "CSP", "see P12", "P12", "",
    "SCRM team designation in P12.")
add("SR-3", "Supply Chain Controls and Processes", "Partial", "System", ".github/workflows/release.yml", "P6", "POAM-006",
    "SBOM generation exists but unverified at consumption; provenance + verification controls in P6.")
add("SR-4", "Provenance", "Planned", "System", ".github/workflows/release.yml", "P6", "POAM-006",
    "SLSA provenance attestation (build-by-digest) added in P6.")
add("SR-5", "Acquisition Strategies, Tools, and Methods", "Planned", "System", "see P6", "P6", "",
    "Pinned dependencies/actions + acquisition controls in P1/P6.")
add("SR-6", "Supplier Assessments and Reviews", "Planned", "CSP", "see P6", "P6", "", "Supplier/dependency review in P6.")
add("SR-8", "Notification Agreements", "Planned", "CSP", "see P12", "P12", "", "Supplier notification agreements in P12.")
add("SR-9", "Tamper Resistance and Detection", "Planned", "System", "see P6", "P6", "POAM-006",
    "Image digest pinning + signature verification provide tamper detection in P6.")
add("SR-10", "Inspection of Systems or Components", "Planned", "System", "see P6", "P6", "",
    "Component inspection via SBOM/scan/verify in P6.")
add("SR-11", "Component Authenticity", "Planned", "System", "see P6", "P6", "POAM-006",
    "Cosign signature verification establishes authenticity in P6.")
add("SR-11(1)", "Component Authenticity | Anti-Counterfeit Training", "Planned", "CSP", "see P12", "P12", "",
    "Anti-counterfeit awareness in P12.")
add("SR-11(2)", "Component Authenticity | Configuration Control for Component Service and Repair", "Planned",
    "System", "see P6", "P6", "", "Config control for component repair via GitOps in P6.")
add("SR-12", "Component Disposal", "Planned", "Shared", "see P12", "P12", "", "Component/image disposal procedure in P12.")

# ---------------------------------------------------------------------------
# PM - Program Management (organization-wide; not baseline-allocated but tracked)
# ---------------------------------------------------------------------------
add("PM-1", "Information Security Program Plan", "Planned", "CSP", "see P12", "P12", "", "Org infosec program plan (P12).")
add("PM-2", "Information Security Program Leadership Role", "Planned", "CSP", "see P12", "P12", "",
    "ISSO/senior-official role (TBD - assign) designated in P12.")
add("PM-3", "Information Security and Privacy Resources", "Planned", "CSP", "see P12", "P12", "", "Program resourcing in P12.")
add("PM-4", "Plan of Action and Milestones Process", "Partial", "CSP", "docs/compliance/poam.csv", "P0", "",
    "POA&M process established (poam.csv); program-level tracking matured in P12.")
add("PM-5", "System Inventory", "Partial", "CSP", "docs/compliance/inventory.csv", "P0", "",
    "System inventory established (AST-*); org-wide inventory program in P12.")
add("PM-6", "Measures of Performance", "Planned", "CSP", "see P9", "P9", "", "Security performance measures via ConMon metrics in P9/P12.")
add("PM-7", "Enterprise Architecture", "Planned", "CSP", "see P12", "P12", "", "Enterprise architecture alignment in P12.")
add("PM-9", "Risk Management Strategy", "Planned", "CSP", "see P12", "P12", "", "Org risk-management strategy in P12.")
add("PM-10", "Authorization Process", "Planned", "CSP", "see P12", "P12", "", "Authorization/ATO process in P12.")
add("PM-11", "Mission and Business Process Definition", "Planned", "CSP", "see P12", "P12", "", "Mission/business process definition in P12.")


def resolve(row):
    cid, title, status, rp, art, phase, poam, notes = row
    fam = cid.split("-")[0]
    if rp is None:
        rp = FAMILY_RP[fam]
    if art is None:
        art = see_phase(fam)
    if phase is None:
        phase = FAMILY_PHASE[fam]
    return {
        "control_id": cid,
        "title": title,
        "family": fam,
        "baseline": "Moderate",
        "status": status,
        "responsible_party": rp,
        "implementing_artifact": art,
        "remediating_phase": phase,
        "poam_id": poam,
        "notes": notes,
    }


def build():
    rows = [resolve(r) for r in R]
    # validation
    seen = set()
    valid_status = {"Implemented", "Partial", "Planned", "Inherited", "Customer", "Not-Applicable"}
    valid_rp = {"System", "CSP", "Customer", "Shared"}
    for r in rows:
        assert r["control_id"] not in seen, f"duplicate {r['control_id']}"
        seen.add(r["control_id"])
        assert r["status"] in valid_status, f"bad status {r['control_id']}={r['status']}"
        assert r["responsible_party"] in valid_rp, f"bad rp {r['control_id']}={r['responsible_party']}"
        assert r["status"].strip(), f"blank status {r['control_id']}"
        assert r["responsible_party"].strip(), f"blank rp {r['control_id']}"
    header = ["control_id", "title", "family", "baseline", "status",
              "responsible_party", "implementing_artifact", "remediating_phase",
              "poam_id", "notes"]
    out = "docs/compliance/control-matrix.csv"
    with open(out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=header)
        w.writeheader()
        for r in rows:
            w.writerow(r)
    # stats
    from collections import Counter
    by_status = Counter(r["status"] for r in rows)
    by_fam = Counter(r["family"] for r in rows)
    print(f"wrote {len(rows)} rows -> {out}")
    print("by status:", dict(by_status))
    print("by family:", dict(sorted(by_fam.items())))
    return rows


if __name__ == "__main__":
    build()
