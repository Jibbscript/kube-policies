# Security Diagrams — pointer

The threat model under `docs/security/` is a [pointer](../threat-model.md) to the **canonical**
threat model at [`../../compliance/threat-model.md`](../../compliance/threat-model.md). To avoid
duplication, it does **not** maintain its own diagrams.

The authoritative diagrams referenced by the threat model live under the compliance artifacts:

### → [`../../compliance/diagrams/`](../../compliance/diagrams/)

- [Data Flow Diagram](../../compliance/diagrams/data-flow.md) — the trust-boundary crossings
  (`ICX-01..06`) analyzed in the threat model's per-crossing STRIDE tables.
- [Authorization Boundary Diagram](../../compliance/diagrams/authorization-boundary.md) — the
  assessed authorization boundary (`ZONE-EXT`/`ZONE-SYS`) and component placement.

All diagrams use the canonical asset IDs (`AST-*`), ports, trust zones, and interconnection IDs
(`ICX-01..06`) from the [System Facts Sheet](../../compliance/system-facts.md).
