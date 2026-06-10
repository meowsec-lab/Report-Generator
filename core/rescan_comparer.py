"""
Rescan Comparison module for the Nessus Report Generator.

Compares current scan results (list of Finding dicts) with a previous
Excel report to assign status: New / Open / Resolved.
"""

import logging
from pathlib import Path
from typing import Callable, Optional

import openpyxl

from config import SEVERITY_ORDER
from core.csv_processor import Finding, get_severity_counts

logger = logging.getLogger(__name__)


# =============================================================================
# Exceptions
# =============================================================================

class RescanCompareError(Exception):
    """Custom exception for rescan comparison errors."""

    def __init__(self, message: str, details: str = "") -> None:
        self.message = message
        self.details = details
        super().__init__(message)


# =============================================================================
# Previous report loading
# =============================================================================

def _load_previous_excel(
    filepath: str,
    progress_callback: Optional[Callable[[str, float], None]] = None,
) -> list[Finding]:
    """
    Load findings from a previous Excel report's 'Findings' sheet.

    Returns a list of Finding dicts.
    """
    if progress_callback:
        progress_callback("Loading previous report...", 5)

    try:
        wb = openpyxl.load_workbook(filepath, read_only=True, data_only=True)
    except PermissionError:
        raise RescanCompareError(
            "Cannot read previous report",
            f"Permission denied. The file may be open: {filepath}",
        )
    except Exception as exc:
        raise RescanCompareError("Error loading previous report", str(exc))

    if "Findings" not in wb.sheetnames:
        wb.close()
        raise RescanCompareError(
            "Invalid previous report",
            "The Excel file is missing the 'Findings' sheet.",
        )

    ws = wb["Findings"]
    data = list(ws.values)
    wb.close()

    if not data:
        raise RescanCompareError("Empty previous report", "No data in Findings sheet.")

    headers = [str(h) if h else "" for h in data[0]]
    rows: list[Finding] = []
    for raw in data[1:]:
        row: Finding = {}
        for i, hdr in enumerate(headers):
            val = raw[i] if i < len(raw) else None
            row[hdr] = str(val).strip() if val is not None and str(val) != "None" else ""
        rows.append(row)

    logger.info("Loaded %d findings from previous report", len(rows))
    return rows


# =============================================================================
# Key building
# =============================================================================

def _finding_key(row: Finding) -> str:
    """Build a comparison key: ip|issue_name|port  (lowercased, stripped)."""
    ip = (row.get("IP Address", "") or row.get("ip_address", "")).strip().lower()
    issue = (
        row.get("Issue Name", "")
        or row.get("plugin_name", "")
        or row.get("Plugin Name", "")
    ).strip().lower()
    port = (row.get("Port", "") or row.get("port", "")).strip()
    return f"{ip}|{issue}|{port}"


# =============================================================================
# Comparison
# =============================================================================

def _compare_findings(
    current: list[Finding],
    previous: list[Finding],
    progress_callback: Optional[Callable[[str, float], None]],
) -> tuple[list[Finding], dict[str, int]]:
    """
    Compare current vs previous findings and assign Status.

    Returns (merged_rows, status_counts).
    """
    if progress_callback:
        progress_callback("Comparing findings...", 50)

    current_keys = {_finding_key(r) for r in current}
    previous_keys = {_finding_key(r) for r in previous}

    new_keys = current_keys - previous_keys
    open_keys = current_keys & previous_keys
    closed_keys = previous_keys - current_keys

    logger.info("Comparison: %d new, %d open, %d resolved",
                len(new_keys), len(open_keys), len(closed_keys))

    # Assign status to current rows
    if progress_callback:
        progress_callback("Assigning statuses...", 55)

    for row in current:
        key = _finding_key(row)
        row["Status"] = "New" if key in new_keys else "Open"

    # Build resolved rows from previous
    if progress_callback:
        progress_callback("Processing resolved findings...", 58)

    prev_by_key = {_finding_key(r): r for r in previous}
    resolved_rows: list[Finding] = []

    for key in closed_keys:
        row = prev_by_key[key].copy()
        row["Status"] = "Resolved"
        if "Plugin Output" in row:
            row["Plugin Output"] = "[Remediated - No longer detected]"
        resolved_rows.append(row)

    # Merge
    merged = current + resolved_rows

    status_counts = {
        "New": len(new_keys),
        "Open": len(open_keys),
        "Resolved": len(closed_keys),
    }
    logger.info("Merged: %d total findings", len(merged))
    return merged, status_counts


# =============================================================================
# Sorting
# =============================================================================

_STATUS_ORDER = {"New": 0, "Open": 1, "Resolved": 2}


def _sort_rescan(rows: list[Finding]) -> list[Finding]:
    """Sort by status (New → Open → Resolved) then by severity."""
    def _key(r: Finding) -> tuple[int, int]:
        return (
            _STATUS_ORDER.get(r.get("Status", "Open"), 1),
            SEVERITY_ORDER.get(r.get("Severity", "Informational"), 4),
        )

    rows.sort(key=_key)
    return rows


# =============================================================================
# Public API
# =============================================================================

def process_rescan(
    current_rows: list[Finding],
    previous_filepath: str,
    progress_callback: Optional[Callable[[str, float], None]] = None,
) -> tuple[list[Finding], dict[str, int], dict[str, int]]:
    """
    Main rescan entry-point.

    Args:
        current_rows:      Processed current-scan findings.
        previous_filepath: Path to previous Excel report.
        progress_callback: Optional (message, pct) callback.

    Returns:
        (merged_rows, status_counts, previous_severity_counts)
    """
    previous_rows = _load_previous_excel(previous_filepath, progress_callback)
    previous_severity_counts = get_severity_counts(previous_rows)

    merged, status_counts = _compare_findings(
        current_rows, previous_rows, progress_callback,
    )

    if progress_callback:
        progress_callback("Sorting rescan results...", 65)

    merged = _sort_rescan(merged)
    return merged, status_counts, previous_severity_counts
