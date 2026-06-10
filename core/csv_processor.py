"""
CSV Processing module for the Nessus Report Generator.

Handles reading CSV files with encoding fallback (streaming via csv.DictReader),
column normalization, severity derivation, plugin omission rules, and
data consolidation / deduplication.

OMISSION LOGIC (applied to every row):
  1. If plugin_name is in ALWAYS_OMIT → omit.
  2. If plugin_name is in SELF_SIGNED_PLUGINS:
       - Host IP is valid IPv4 AND in 192.168.195.0/24 → KEEP.
       - Otherwise → omit.
  3. All other rows → keep.
"""

import csv
import ipaddress
import logging
import sys
from io import StringIO
from pathlib import Path
from typing import Callable, Optional

# Increase CSV field size limit to handle huge Nessus "Plugin Output" fields
csv.field_size_limit(min(sys.maxsize, 2147483646))

from config import (
    ALWAYS_OMIT,
    COLUMN_MAPPINGS,
    COLUMN_RENAMES,
    CVSS_SEVERITY_RANGES,
    DEDUP_KEYS,
    ENCODING_FALLBACK,
    OUTPUT_COLUMNS_NEW,
    SELF_SIGNED_PLUGINS,
    SEVERITY_NORMALIZATION,
    SEVERITY_ORDER,
    SUBNET_EXEMPTION,
)

logger = logging.getLogger(__name__)

# Type alias for a single finding (dict of str→str).
Finding = dict[str, str]


# =============================================================================
# Exceptions
# =============================================================================

class CSVProcessingError(Exception):
    """Custom exception for CSV processing errors."""

    def __init__(self, message: str, details: str = "") -> None:
        self.message = message
        self.details = details
        super().__init__(message)


# =============================================================================
# CSV Reading — streaming with encoding fallback
# =============================================================================

def _detect_encoding(filepath: str) -> str:
    """Try chardet first, fall back to the ENCODING_FALLBACK list."""
    try:
        import chardet
        raw = Path(filepath).read_bytes(8192 if Path(filepath).stat().st_size > 8192
                                         else None)
        detection = chardet.detect(raw)
        if detection and detection.get("encoding"):
            logger.debug("chardet detected encoding: %s (confidence %.0f%%)",
                         detection["encoding"], (detection.get("confidence", 0) or 0) * 100)
            return detection["encoding"]
    except ImportError:
        logger.debug("chardet not available — using fallback list")
    except Exception as exc:
        logger.debug("chardet failed: %s", exc)
    return ""


def _try_read_lines(filepath: str, encoding: str) -> list[str]:
    """Read all lines with the given encoding. Raises on failure."""
    with open(filepath, "r", encoding=encoding, errors="strict", newline="") as fh:
        return fh.readlines()


def read_csv_rows(
    filepath: str,
    progress_callback: Optional[Callable[[str], None]] = None,
) -> list[Finding]:
    """
    Read a CSV file into a list of row-dicts using streaming csv.DictReader.

    Tries chardet → ENCODING_FALLBACK list.  Returns a list because downstream
    needs random-access for sorting / dedup.  For typical Nessus exports
    (<200 k rows) this is acceptable; for truly huge files, switch to an
    on-disk sort (e.g. SQLite temp table).

    Raises:
        CSVProcessingError: If the file cannot be decoded or is empty.
    """
    filename = Path(filepath).name
    if progress_callback:
        progress_callback(f"Reading {filename}...")

    # Build candidate encoding list
    encodings: list[str] = []
    detected = _detect_encoding(filepath)
    if detected:
        encodings.append(detected)
    encodings.extend(ENCODING_FALLBACK)

    last_error: Optional[Exception] = None
    lines: list[str] = []

    for enc in encodings:
        try:
            logger.debug("Trying encoding %s for %s", enc, filename)
            lines = _try_read_lines(filepath, enc)
            logger.info("Read %s with %s encoding (%d lines)", filename, enc, len(lines))
            break
        except (UnicodeDecodeError, LookupError) as exc:
            last_error = exc
            continue
    else:
        # Last resort — utf-8 with replacement
        logger.warning("All strict decodings failed for %s — using utf-8 with replacement", filename)
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace", newline="") as fh:
                lines = fh.readlines()
        except Exception as exc:
            raise CSVProcessingError(
                f"Cannot read {filename}",
                f"All encodings failed. Last error: {last_error or exc}",
            ) from exc

    if not lines or all(not line.strip() for line in lines):
        raise CSVProcessingError(f"Empty CSV file: {filename}", "No data rows found.")

    reader = csv.DictReader(StringIO("".join(lines)))
    rows: list[Finding] = []
    for row in reader:
        rows.append({k: (v or "") for k, v in row.items()})

    if not rows:
        raise CSVProcessingError(
            f"Empty CSV file: {filename}",
            "The file contains headers but no data rows.",
        )

    logger.info("Parsed %d rows from %s", len(rows), filename)
    return rows


# =============================================================================
# Column normalization
# =============================================================================

def normalize_column_name(column: str) -> str:
    """Map a raw CSV header to its standardized internal name (or pass-through)."""
    col_lower = column.lower().strip()
    for internal_name, variations in COLUMN_MAPPINGS.items():
        if col_lower in variations:
            return internal_name
    return column.strip()


# Known text-based severity labels (lowercase) — used to resolve column collisions.
_SEVERITY_TEXT_LABELS: frozenset[str] = frozenset({
    "critical", "crit", "high", "medium", "med", "moderate",
    "low", "informational", "info", "none",
})


def normalize_row(raw_row: Finding) -> Finding:
    """
    Rename the keys of a single row dict to internal column names.

    Collision policy:
      - **severity**: text labels ("High") are preferred over numeric codes
        ("2") so the scanner's authoritative risk assessment is preserved.
      - **all other fields**: last value wins (same as the original dict-
        comprehension behavior) to avoid breaking CSVs where multiple
        columns map to the same internal name (e.g. "Plugin" + "Name"
        both map to plugin_name — we want the more descriptive one,
        which is typically the later column).
    """
    result: Finding = {}
    for k, v in raw_row.items():
        normalized = normalize_column_name(k)
        if normalized == "severity":
            # Collision on severity key — prefer text label over numeric code.
            if normalized not in result:
                result[normalized] = v
            elif v:
                new_val = v.strip().lower()
                existing_val = result[normalized].strip().lower()
                new_is_text = new_val in _SEVERITY_TEXT_LABELS
                existing_is_text = existing_val in _SEVERITY_TEXT_LABELS
                if new_is_text and not existing_is_text:
                    logger.debug(
                        "Severity collision: keeping text '%s' over numeric '%s'",
                        v.strip(), result[normalized].strip(),
                    )
                    result[normalized] = v
                # Otherwise keep existing (first text wins)
        else:
            # All other fields: last value wins (preserves original behavior).
            result[normalized] = v
    return result


# =============================================================================
# Severity derivation
# =============================================================================

def cvss_to_severity(score_str: str) -> str:
    """Convert a CVSS score string to a severity label."""
    try:
        score = float(score_str)
    except (ValueError, TypeError):
        return "Informational"
    if score > 10.0:
        return "Critical"
    for severity, (low, high) in CVSS_SEVERITY_RANGES.items():
        if low <= score <= high:
            return severity
    return "Informational"


def derive_severity(row: Finding) -> str:
    """
    Normalize severity.  Priority: severity text → CVSS v3 → CVSS v2 → Informational.

    The scanner's own text-based severity (e.g. "High") is authoritative and
    is always respected.  CVSS-based derivation is used ONLY as a fallback
    when no text severity is present.
    """
    sev_raw = row.get("severity", "").strip().lower()
    # Only use text-based severity if it's a meaningful, non-empty value.
    # Empty / "nan" should fall through to CVSS-based derivation.
    if sev_raw and sev_raw != "nan" and sev_raw in SEVERITY_NORMALIZATION:
        return SEVERITY_NORMALIZATION[sev_raw]

    # Fallback to CVSS scores only when text severity is absent.
    cvss3 = row.get("cvss_v3_base_score", "").strip()
    if cvss3:
        derived = cvss_to_severity(cvss3)
        logger.debug("No text severity; derived '%s' from CVSS v3 score %s", derived, cvss3)
        return derived

    cvss2 = row.get("cvss_v2_base_score", "").strip()
    if cvss2:
        derived = cvss_to_severity(cvss2)
        logger.debug("No text severity; derived '%s' from CVSS v2 score %s", derived, cvss2)
        return derived

    return "Informational"


# =============================================================================
# Plugin omission rules (pure function)
# =============================================================================

def ip_in_subnet(host: str) -> bool:
    """Return True if *host* is a valid IPv4 address inside SUBNET_EXEMPTION."""
    try:
        addr = ipaddress.ip_address(host.strip())
        return addr in SUBNET_EXEMPTION
    except (ValueError, AttributeError):
        return False


def should_omit_row(row: Finding) -> bool:
    """
    Decide whether a single finding row should be omitted.

    Returns True if the row should be dropped.
    """
    plugin_name = row.get("plugin_name", "").strip().lower()

    if plugin_name in ALWAYS_OMIT:
        return True

    if plugin_name in SELF_SIGNED_PLUGINS:
        host = row.get("ip_address", "").strip()
        # Keep if host IP is in the exempt subnet
        if ip_in_subnet(host):
            return False
        return True

    return False


def apply_omission_rules(
    rows: list[Finding],
    progress_callback: Optional[Callable[[str, float], None]] = None,
) -> list[Finding]:
    """
    Apply the two-tier omission rules to all rows.  Returns the filtered list.
    """
    if progress_callback:
        progress_callback("Applying omission rules...", 42)

    kept: list[Finding] = []
    omitted_count = 0

    for row in rows:
        if should_omit_row(row):
            omitted_count += 1
            logger.debug("Omitted: plugin=%s host=%s",
                         row.get("plugin_name", ""), row.get("ip_address", ""))
        else:
            kept.append(row)

    logger.info("Omission rules: removed %d / %d rows", omitted_count, len(rows))
    return kept


# =============================================================================
# Deduplication
# =============================================================================

def _dedup_key(row: Finding) -> str:
    """Build a deduplication key from the row (ip|plugin_name|port)."""
    parts = [row.get(k, "").strip().lower() for k in DEDUP_KEYS]
    return "|".join(parts)


def remove_duplicates(
    rows: list[Finding],
    progress_callback: Optional[Callable[[str, float], None]] = None,
) -> list[Finding]:
    """Remove duplicate findings (keep first occurrence)."""
    if progress_callback:
        progress_callback("Removing duplicates...", 50)

    seen: set[str] = set()
    unique: list[Finding] = []

    for row in rows:
        key = _dedup_key(row)
        if key not in seen:
            seen.add(key)
            unique.append(row)

    removed = len(rows) - len(unique)
    logger.info("Dedup: removed %d duplicates, %d remaining", removed, len(unique))
    return unique


# =============================================================================
# Sorting
# =============================================================================

def sort_by_severity(
    rows: list[Finding],
    progress_callback: Optional[Callable[[str, float], None]] = None,
) -> list[Finding]:
    """
    Sort findings by severity (Critical first) then IP address.

    Trade-off note: For typical Nessus reports (<200 k rows), in-memory
    sorting with Python's timsort is fast and efficient.  For CSV files
    approaching 500 MB (millions of rows), consider an external/merge sort
    or loading into a SQLite temp table.
    """
    if progress_callback:
        progress_callback("Sorting results...", 60)

    def _sort_key(row: Finding) -> tuple[int, str]:
        sev = SEVERITY_ORDER.get(row.get("severity", "Informational"), 4)
        ip = row.get("ip_address", "")
        return (sev, ip)

    rows.sort(key=_sort_key)
    return rows


# =============================================================================
# Column renaming for output
# =============================================================================

def rename_for_output(row: Finding) -> Finding:
    """Rename internal column names to their display names for Excel output."""
    return {COLUMN_RENAMES.get(k, k): v for k, v in row.items()}


def ensure_output_columns(row: Finding) -> Finding:
    """Ensure all OUTPUT_COLUMNS_NEW keys exist (missing → '')."""
    for col in OUTPUT_COLUMNS_NEW:
        if col != "Serial" and col not in row:
            row[col] = ""
    return row


# =============================================================================
# Aggregation helpers (pure functions)
# =============================================================================

def get_severity_counts(rows: list[Finding]) -> dict[str, int]:
    """Return a {severity: count} dict with all five levels present."""
    counts: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    sev_key = "Severity" if rows and "Severity" in rows[0] else "severity"
    for row in rows:
        sev = row.get(sev_key, "Informational")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def get_ip_summary(rows: list[Finding]) -> list[dict[str, object]]:
    """
    Build an IP summary table: one row per IP with severity counts + total.
    Returns a list of dicts suitable for writing an Excel sheet.
    """
    ip_key = "IP Address" if rows and "IP Address" in rows[0] else "ip_address"
    sev_key = "Severity" if rows and "Severity" in rows[0] else "severity"

    ip_data: dict[str, dict[str, int]] = {}

    for row in rows:
        ip = row.get(ip_key, "Unknown")
        sev = row.get(sev_key, "Informational")
        if ip not in ip_data:
            ip_data[ip] = {s: 0 for s in SEVERITY_ORDER}
        ip_data[ip][sev] = ip_data[ip].get(sev, 0) + 1

    summary: list[dict[str, object]] = []
    for ip in sorted(ip_data, key=lambda x: sum(ip_data[x].values()), reverse=True):
        entry: dict[str, object] = {"IP Address": ip}
        total = 0
        for sev in ["Critical", "High", "Medium", "Low", "Informational"]:
            count = ip_data[ip].get(sev, 0)
            entry[sev] = count
            total += count
        entry["Total"] = total
        summary.append(entry)

    return summary


# =============================================================================
# Main pipeline
# =============================================================================

def process_csv_files(
    filepaths: list[str],
    progress_callback: Optional[Callable[[str, float], None]] = None,
    omit_ssl: bool = False,  # kept for API compat; omission always runs
) -> list[Finding]:
    """
    End-to-end pipeline: read → normalize → omit → derive severity →
    dedup → sort → rename → ensure columns.

    Args:
        filepaths:         One or more CSV file paths.
        progress_callback: Optional (message, percentage) callback.
        omit_ssl:          Ignored (kept for backward API compatibility).
                           Omission rules always apply.

    Returns:
        A list of Finding dicts ready for Excel output.

    Raises:
        CSVProcessingError on unrecoverable issues.
    """
    def update(msg: str, pct: float = 0) -> None:
        if progress_callback:
            progress_callback(msg, pct)

    # 1. Read & normalize ──────────────────────────────────────────────
    all_rows: list[Finding] = []
    total_files = len(filepaths)

    for idx, fp in enumerate(filepaths):
        pct = (idx / max(total_files, 1)) * 40
        update(f"Reading file {idx + 1}/{total_files}...", pct)
        raw_rows = read_csv_rows(fp)
        normalized = [normalize_row(r) for r in raw_rows]
        all_rows.extend(normalized)

    if not all_rows:
        raise CSVProcessingError("No data", "All CSV files were empty.")

    logger.info("Total raw rows after merge: %d", len(all_rows))

    # 2. Omission rules (always applied) ───────────────────────────────
    all_rows = apply_omission_rules(all_rows, progress_callback)

    # 3. Derive severity ───────────────────────────────────────────────
    update("Deriving severity levels...", 45)
    for row in all_rows:
        row["severity"] = derive_severity(row)

    # 4. Deduplication ─────────────────────────────────────────────────
    all_rows = remove_duplicates(all_rows, progress_callback)

    # 5. Sort ──────────────────────────────────────────────────────────
    all_rows = sort_by_severity(all_rows, progress_callback)

    # 6. Rename & ensure output columns ────────────────────────────────
    update("Preparing output...", 65)
    all_rows = [ensure_output_columns(rename_for_output(r)) for r in all_rows]

    update("Data processing complete", 70)
    logger.info("Processing complete. Final row count: %d", len(all_rows))
    return all_rows
