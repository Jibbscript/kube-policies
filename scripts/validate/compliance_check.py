#!/usr/bin/env python3
"""Offline compliance CI validators for docs/compliance and docs/security.

Implements the P0 compliance gates:
  (a) control-matrix.csv  — no blank 'status' or 'responsible_party'
  (b) poam.csv            — no blank 'severity' or 'scheduled_completion'
  (c) inventory.csv       — asset_id non-blank and unique; every In-Boundary/
                            Inherited asset_id beginning with 'AST-' must appear
                            in docs/compliance/diagrams/authorization-boundary.md
                            (inventory <-> boundary consistency)
  (d) relative markdown link checker over docs/compliance/**/*.md,
      docs/security/**/*.md and SECURITY.md — every [text](relpath) (ignoring
      http/https/anchor-only/mailto) must resolve to an existing file/dir.

Exit code 0 on PASS, 1 on any FAILURE. No third-party dependencies.
"""

from __future__ import annotations

import csv
import os
import re
import sys
from pathlib import Path

# Repository root = two levels up from scripts/validate/.
REPO_ROOT = Path(__file__).resolve().parents[2]

COMPLIANCE_DIR = REPO_ROOT / "docs" / "compliance"
SECURITY_DIR = REPO_ROOT / "docs" / "security"
CONTROL_MATRIX = COMPLIANCE_DIR / "control-matrix.csv"
POAM = COMPLIANCE_DIR / "poam.csv"
INVENTORY = COMPLIANCE_DIR / "inventory.csv"
BOUNDARY = COMPLIANCE_DIR / "diagrams" / "authorization-boundary.md"
SECURITY_MD = REPO_ROOT / "SECURITY.md"

# Markdown link: [text](target). Captures the raw target (may include #anchor).
LINK_RE = re.compile(r"\[(?:[^\]]*)\]\(([^)]+)\)")
# Targets we deliberately ignore: external URLs, anchor-only, mailto, protocols.
IGNORE_PREFIXES = ("http://", "https://", "#", "mailto:", "tel:")


def _rel(p: Path) -> str:
    """Path relative to repo root for tidy reporting (falls back to abs)."""
    try:
        return str(p.resolve().relative_to(REPO_ROOT))
    except ValueError:
        return str(p)


def _read_rows(path: Path):
    """Yield (lineno, row-dict) for a CSV with a header row.

    Returns (header, rows) or raises on a missing/empty file so the caller
    can record a failure deterministically.
    """
    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames is None:
            raise ValueError(f"{_rel(path)}: empty or headerless CSV")
        rows = list(reader)
        return reader.fieldnames, rows


def _blank(value) -> bool:
    return value is None or value.strip() == ""


# ---------------------------------------------------------------------------
# (a) control-matrix.csv
# ---------------------------------------------------------------------------
def check_control_matrix(failures: list[str]) -> int:
    if not CONTROL_MATRIX.exists():
        failures.append(f"(a) missing file: {_rel(CONTROL_MATRIX)}")
        return 0
    checked = 0
    try:
        header, rows = _read_rows(CONTROL_MATRIX)
    except Exception as exc:  # noqa: BLE001 - surface any parse error as a failure
        failures.append(f"(a) {exc}")
        return 0
    for col in ("control_id", "status", "responsible_party"):
        if col not in header:
            failures.append(
                f"(a) {_rel(CONTROL_MATRIX)}: missing required column '{col}'"
            )
    if "status" not in header or "responsible_party" not in header:
        return 0
    for i, row in enumerate(rows, start=2):  # line 1 is the header
        checked += 1
        cid = (row.get("control_id") or "").strip() or f"row {i}"
        if _blank(row.get("status")):
            failures.append(
                f"(a) {_rel(CONTROL_MATRIX)}:{i} control '{cid}' has blank 'status'"
            )
        if _blank(row.get("responsible_party")):
            failures.append(
                f"(a) {_rel(CONTROL_MATRIX)}:{i} control '{cid}' "
                "has blank 'responsible_party'"
            )
    return checked


# ---------------------------------------------------------------------------
# (b) poam.csv
# ---------------------------------------------------------------------------
def check_poam(failures: list[str]) -> int:
    if not POAM.exists():
        failures.append(f"(b) missing file: {_rel(POAM)}")
        return 0
    checked = 0
    try:
        header, rows = _read_rows(POAM)
    except Exception as exc:  # noqa: BLE001
        failures.append(f"(b) {exc}")
        return 0
    for col in ("poam_id", "severity", "scheduled_completion"):
        if col not in header:
            failures.append(f"(b) {_rel(POAM)}: missing required column '{col}'")
    if "severity" not in header or "scheduled_completion" not in header:
        return 0
    for i, row in enumerate(rows, start=2):
        checked += 1
        pid = (row.get("poam_id") or "").strip() or f"row {i}"
        if _blank(row.get("severity")):
            failures.append(
                f"(b) {_rel(POAM)}:{i} POA&M '{pid}' has blank 'severity'"
            )
        if _blank(row.get("scheduled_completion")):
            failures.append(
                f"(b) {_rel(POAM)}:{i} POA&M '{pid}' "
                "has blank 'scheduled_completion'"
            )
    return checked


# ---------------------------------------------------------------------------
# (c) inventory.csv + inventory <-> boundary consistency
# ---------------------------------------------------------------------------
def check_inventory(failures: list[str]) -> int:
    if not INVENTORY.exists():
        failures.append(f"(c) missing file: {_rel(INVENTORY)}")
        return 0
    checked = 0
    try:
        header, rows = _read_rows(INVENTORY)
    except Exception as exc:  # noqa: BLE001
        failures.append(f"(c) {exc}")
        return 0
    if "asset_id" not in header:
        failures.append(
            f"(c) {_rel(INVENTORY)}: missing required column 'asset_id'"
        )
        return 0

    boundary_text = ""
    if BOUNDARY.exists():
        boundary_text = BOUNDARY.read_text(encoding="utf-8")
    else:
        failures.append(f"(c) missing boundary diagram: {_rel(BOUNDARY)}")

    seen: dict[str, int] = {}
    for i, row in enumerate(rows, start=2):
        checked += 1
        asset_id = (row.get("asset_id") or "").strip()
        if asset_id == "":
            failures.append(f"(c) {_rel(INVENTORY)}:{i} has a blank 'asset_id'")
            continue
        if asset_id in seen:
            failures.append(
                f"(c) {_rel(INVENTORY)}:{i} duplicate asset_id '{asset_id}' "
                f"(first seen line {seen[asset_id]})"
            )
        else:
            seen[asset_id] = i

        # inventory <-> boundary consistency: every in-boundary AST-* asset
        # must be named in the authorization-boundary diagram. External assets
        # (boundary == External) are intentionally not pinned to an AST-* ID in
        # the diagram, so they are exempt from the presence requirement.
        boundary_class = (row.get("boundary") or "").strip().lower()
        if (
            asset_id.startswith("AST-")
            and boundary_class != "external"
            and boundary_text
            and asset_id not in boundary_text
        ):
            failures.append(
                f"(c) {_rel(INVENTORY)}:{i} asset_id '{asset_id}' "
                f"(boundary={row.get('boundary') or '?'}) not found in "
                f"{_rel(BOUNDARY)} (inventory<->boundary mismatch)"
            )
    return checked


# ---------------------------------------------------------------------------
# (d) relative markdown link checker
# ---------------------------------------------------------------------------
def _markdown_files() -> list[Path]:
    files: list[Path] = []
    for base in (COMPLIANCE_DIR, SECURITY_DIR):
        if base.is_dir():
            files.extend(sorted(base.rglob("*.md")))
    if SECURITY_MD.exists():
        files.append(SECURITY_MD)
    return files


def check_links(failures: list[str]) -> int:
    checked = 0
    for md in _markdown_files():
        try:
            text = md.read_text(encoding="utf-8")
        except OSError as exc:
            failures.append(f"(d) cannot read {_rel(md)}: {exc}")
            continue
        for match in LINK_RE.finditer(text):
            raw = match.group(1).strip()
            if not raw:
                continue
            # Markdown allows an optional title: [t](path "title"); drop it.
            target = raw.split()[0]
            lowered = target.lower()
            if lowered.startswith(IGNORE_PREFIXES):
                continue
            # Strip any anchor / query fragment; keep the path portion.
            path_part = target.split("#", 1)[0].split("?", 1)[0]
            if path_part == "":
                continue  # was anchor-only after split
            checked += 1
            resolved = (md.parent / path_part).resolve()
            if not resolved.exists():
                lineno = text.count("\n", 0, match.start()) + 1
                failures.append(
                    f"(d) {_rel(md)}:{lineno} broken relative link "
                    f"'{target}' -> {_rel(resolved)} (target does not exist)"
                )
    return checked


def main() -> int:
    failures: list[str] = []

    print("==> Compliance validation (offline)")
    print(f"    repo root: {REPO_ROOT}")

    n_cm = check_control_matrix(failures)
    n_poam = check_poam(failures)
    n_inv = check_inventory(failures)
    n_links = check_links(failures)

    print("")
    print("Checks performed:")
    print(f"  (a) control-matrix rows checked     : {n_cm}")
    print(f"  (b) poam rows checked               : {n_poam}")
    print(f"  (c) inventory rows checked          : {n_inv}")
    print(f"  (d) relative markdown links checked : {n_links}")
    print("")

    if failures:
        print(f"FAIL: {len(failures)} compliance issue(s) found:")
        for f in failures:
            print(f"  - {f}")
        print("")
        print(f"==> COMPLIANCE: FAIL ({len(failures)} issue(s))")
        return 1

    print("==> COMPLIANCE: PASS (0 issues)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
