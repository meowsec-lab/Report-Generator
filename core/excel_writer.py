"""
Excel Writer module for the Nessus Report Generator.

Uses xlsxwriter in constant-memory mode for efficient writing of large
workbooks.  Implements:
  - Formula injection prevention (prefix =, +, -, @ with single quote)
  - Worksheet name sanitization (max 31 chars, no forbidden chars)
  - Severity / status color coding
  - Frozen header rows
"""

import logging
import re
from io import BytesIO
from typing import Callable, Optional, Union

import xlsxwriter

from config import (
    COLUMN_WIDTHS,
    FORMULA_INJECTION_CHARS,
    HEADER_BG_COLOR,
    HEADER_FONT_COLOR,
    HEADER_ROW_HEIGHT,
    INVALID_SHEET_NAME_CHARS,
    MAX_SHEET_NAME_LENGTH,
    MIN_COLUMN_WIDTH,
    OUTPUT_COLUMNS_NEW,
    OUTPUT_COLUMNS_RESCAN,
    SEVERITY_COLORS,
    SEVERITY_FONT_COLORS,
    STATUS_FONT_COLORS,
)

logger = logging.getLogger(__name__)

# Type alias reused from csv_processor
Finding = dict[str, str]


# =============================================================================
# Exceptions
# =============================================================================

class ExcelWriterError(Exception):
    """Custom exception for Excel writing errors."""

    def __init__(self, message: str, details: str = "") -> None:
        self.message = message
        self.details = details
        super().__init__(message)


# =============================================================================
# Helpers
# =============================================================================

def sanitize_sheet_name(name: str) -> str:
    """
    Sanitize a worksheet name to comply with Excel rules:
      - Max 31 characters
      - No characters from [ ] : * ? / \\
    """
    clean = re.sub(f"[{re.escape(INVALID_SHEET_NAME_CHARS)}]", "_", name)
    return clean[:MAX_SHEET_NAME_LENGTH]


def safe_cell_value(value: object) -> str:
    """
    Sanitize a cell value to prevent Excel formula injection.

    If the string starts with =, +, -, or @, prefix with a single quote.
    """
    text = str(value) if value is not None else ""
    if text and text[0] in FORMULA_INJECTION_CHARS:
        return "'" + text
    return text


# =============================================================================
# Format factories (created once per workbook, reused)
# =============================================================================

def _build_header_format(wb: xlsxwriter.Workbook) -> xlsxwriter.format.Format:
    """Dark-red background, white bold text, centered."""
    return wb.add_format({
        "bold": True,
        "font_color": HEADER_FONT_COLOR,
        "bg_color": HEADER_BG_COLOR,
        "align": "center",
        "valign": "vcenter",
        "text_wrap": True,
        "border": 1,
        "font_size": 11,
    })


def _build_cell_format(wb: xlsxwriter.Workbook) -> xlsxwriter.format.Format:
    """Standard data cell — left-aligned, top-aligned, thin border."""
    return wb.add_format({
        "align": "left",
        "valign": "top",
        "text_wrap": True,
        "border": 1,
        "border_color": "#DDDDDD",
        "font_size": 10,
    })


def _build_center_format(wb: xlsxwriter.Workbook) -> xlsxwriter.format.Format:
    """Center-aligned cell for Serial column."""
    return wb.add_format({
        "align": "center",
        "valign": "top",
        "border": 1,
        "border_color": "#DDDDDD",
        "font_size": 10,
    })


def _build_severity_formats(
    wb: xlsxwriter.Workbook,
) -> dict[str, xlsxwriter.format.Format]:
    """One format per severity level."""
    fmts: dict[str, xlsxwriter.format.Format] = {}
    for sev, bg in SEVERITY_COLORS.items():
        bold = sev in ("Critical", "High", "Medium", "Low")
        fmts[sev] = wb.add_format({
            "bg_color": bg,
            "font_color": SEVERITY_FONT_COLORS.get(sev, "#000000"),
            "bold": bold,
            "align": "center",
            "valign": "top",
            "border": 1,
            "border_color": "#DDDDDD",
            "font_size": 10,
        })
    return fmts


def _build_status_formats(
    wb: xlsxwriter.Workbook,
) -> dict[str, xlsxwriter.format.Format]:
    """One format per status value (font color only)."""
    fmts: dict[str, xlsxwriter.format.Format] = {}
    for status, color in STATUS_FONT_COLORS.items():
        fmts[status] = wb.add_format({
            "font_color": color,
            "bold": True,
            "align": "center",
            "valign": "top",
            "border": 1,
            "border_color": "#DDDDDD",
            "font_size": 10,
        })
    return fmts


# =============================================================================
# Sheet writers
# =============================================================================

def _write_findings_sheet(
    wb: xlsxwriter.Workbook,
    rows: list[Finding],
    include_status: bool,
    progress_callback: Optional[Callable[[str, float], None]],
) -> None:
    """Write the main 'Findings' sheet."""
    sheet_name = sanitize_sheet_name("Findings")
    ws = wb.add_worksheet(sheet_name)

    if progress_callback:
        progress_callback("Writing Findings sheet...", 72)

    columns = OUTPUT_COLUMNS_RESCAN if include_status else OUTPUT_COLUMNS_NEW
    # Keep only columns that exist (Serial is always generated)
    if not include_status:
        columns = [c for c in columns if c != "Status"]

    # Formats
    hdr_fmt = _build_header_format(wb)
    cell_fmt = _build_cell_format(wb)
    center_fmt = _build_center_format(wb)
    sev_fmts = _build_severity_formats(wb)
    status_fmts = _build_status_formats(wb)

    # Header row
    for col_idx, col_name in enumerate(columns):
        ws.write(0, col_idx, col_name, hdr_fmt)
    ws.set_row(0, HEADER_ROW_HEIGHT)
    ws.freeze_panes(1, 0)

    # Data rows
    total_rows = len(rows)
    for row_idx, row in enumerate(rows, start=1):
        if progress_callback and row_idx % 500 == 0:
            pct = 72 + (row_idx / max(total_rows, 1)) * 15
            progress_callback(f"Writing row {row_idx}/{total_rows}...", pct)

        for col_idx, col_name in enumerate(columns):
            if col_name == "Serial":
                ws.write_number(row_idx, col_idx, row_idx, center_fmt)
                continue

            raw = row.get(col_name, "")
            value = safe_cell_value(raw)

            # Choose format
            if col_name == "Severity":
                fmt = sev_fmts.get(str(raw), cell_fmt)
            elif col_name == "Status":
                fmt = status_fmts.get(str(raw), cell_fmt)
            else:
                fmt = cell_fmt

            ws.write_string(row_idx, col_idx, value, fmt)

    # Column widths
    for col_idx, col_name in enumerate(columns):
        width = COLUMN_WIDTHS.get(col_name, MIN_COLUMN_WIDTH)
        ws.set_column(col_idx, col_idx, width)

    logger.info("Findings sheet: %d rows written", total_rows)


def _write_summary_header(
    ws: xlsxwriter.worksheet.Worksheet,
    wb: xlsxwriter.Workbook,
    unique_ips: list[str],
) -> None:
    """Write rows 1-4 of the Summary sheet (Title, Methodology, IP, Note)."""
    label_fmt = wb.add_format({
        "bold": True,
        "font_color": "#FFFFFF",
        "bg_color": "#8B0000",
        "valign": "vcenter",
        "border": 1,
        "font_size": 11,
    })
    title_fmt = wb.add_format({
        "bold": True,
        "font_color": "#FFFFFF",
        "bg_color": "#8B0000",
        "valign": "vcenter",
        "border": 1,
        "font_size": 14,
    })
    wrap_fmt = wb.add_format({
        "text_wrap": True,
        "valign": "vcenter",
        "border": 1,
    })

    ws.set_row(0, 30)

    ws.write(0, 0, "Title:", title_fmt)
    ws.write(0, 1, "", wrap_fmt)
    ws.write(1, 0, "Statement of Methodology:", label_fmt)
    ws.write(1, 1, "", wrap_fmt)
    ws.write(2, 0, "IP:", label_fmt)
    ws.write(2, 1, ", ".join(unique_ips) if unique_ips else "", wrap_fmt)
    ws.write(3, 0, "Note:", label_fmt)
    ws.write(3, 1, "", wrap_fmt)


def _write_summary_new(
    wb: xlsxwriter.Workbook,
    severity_counts: dict[str, int],
    unique_ips: list[str],
    progress_callback: Optional[Callable[[str, float], None]],
) -> None:
    """Write Summary sheet for new-report mode."""
    ws = wb.add_worksheet(sanitize_sheet_name("Summary"))

    if progress_callback:
        progress_callback("Writing Summary sheet...", 90)

    _write_summary_header(ws, wb, unique_ips)

    hdr_fmt = _build_header_format(wb)
    sev_fmts = _build_severity_formats(wb)
    center_fmt = wb.add_format({"align": "center", "border": 1})
    bold_center = wb.add_format({"bold": True, "align": "center", "border": 1})

    # Table header at row 6
    ws.write(6, 0, "Severity", hdr_fmt)
    ws.write(6, 1, "Count", hdr_fmt)

    severity_order = ["Critical", "High", "Medium", "Low", "Informational"]
    total = 0
    for i, sev in enumerate(severity_order):
        row = 7 + i
        count = severity_counts.get(sev, 0)
        total += count
        ws.write(row, 0, sev, sev_fmts.get(sev, center_fmt))
        ws.write(row, 1, count, center_fmt)

    grand_row = 7 + len(severity_order)
    ws.write(grand_row, 0, "Grand Total", bold_center)
    ws.write(grand_row, 1, total, bold_center)

    ws.set_column(0, 0, 16)
    ws.set_column(1, 1, 10)
    logger.info("Summary sheet written (new report)")


def _write_summary_rescan(
    wb: xlsxwriter.Workbook,
    prev_counts: dict[str, int],
    mitigated_counts: dict[str, int],
    current_scan_counts: dict[str, int],
    change_counts: dict[str, int],
    unique_ips: list[str],
    progress_callback: Optional[Callable[[str, float], None]],
) -> None:
    """
    Write Summary sheet for rescan mode.

    Four data columns:
      - Previous Scan:  severity counts from the old report
      - Mitigated:      Resolved-status findings (per severity)
      - Current Scan:   New + Open findings (per severity)
      - Change:         New-only findings (per severity)
    """
    ws = wb.add_worksheet(sanitize_sheet_name("Summary"))

    if progress_callback:
        progress_callback("Writing Summary sheet...", 90)

    _write_summary_header(ws, wb, unique_ips)

    hdr_fmt = _build_header_format(wb)
    sev_fmts = _build_severity_formats(wb)
    center_fmt = wb.add_format({"align": "center", "border": 1})
    bold_center = wb.add_format({"bold": True, "align": "center", "border": 1})

    headers = ["Severity", "Previous Scan", "Mitigated", "Current Scan", "Change"]
    for ci, h in enumerate(headers):
        ws.write(6, ci, h, hdr_fmt)

    severity_order = ["Critical", "High", "Medium", "Low", "Informational"]
    totals = [0, 0, 0, 0]  # prev, mitigated, current, change

    for i, sev in enumerate(severity_order):
        row = 7 + i
        pc = prev_counts.get(sev, 0)
        mc = mitigated_counts.get(sev, 0)
        cc = current_scan_counts.get(sev, 0)
        nc = change_counts.get(sev, 0)
        totals[0] += pc
        totals[1] += mc
        totals[2] += cc
        totals[3] += nc
        ws.write(row, 0, sev, sev_fmts.get(sev, center_fmt))
        ws.write(row, 1, pc, center_fmt)
        ws.write(row, 2, mc, center_fmt)
        ws.write(row, 3, cc, center_fmt)
        ws.write(row, 4, nc, center_fmt)

    grand_row = 7 + len(severity_order)
    ws.write(grand_row, 0, "Grand Total", bold_center)
    for ci, t in enumerate(totals):
        ws.write(grand_row, ci + 1, t, bold_center)

    ws.set_column(0, 0, 16)
    ws.set_column(1, 1, 16)
    ws.set_column(2, 2, 14)
    ws.set_column(3, 3, 16)
    ws.set_column(4, 4, 12)
    logger.info("Summary sheet written (rescan)")


def _write_ip_summary_sheet(
    wb: xlsxwriter.Workbook,
    ip_summary: list[dict[str, object]],
    progress_callback: Optional[Callable[[str, float], None]],
) -> None:
    """Write the IP-Summary sheet."""
    ws = wb.add_worksheet(sanitize_sheet_name("IP-Summary"))

    if progress_callback:
        progress_callback("Writing IP-Summary sheet...", 95)

    if not ip_summary:
        ws.write(0, 0, "No data available")
        return

    hdr_fmt = _build_header_format(wb)
    sev_fmts = _build_severity_formats(wb)
    center_fmt = wb.add_format({"align": "center", "border": 1})

    columns = list(ip_summary[0].keys())
    for ci, col in enumerate(columns):
        ws.write(0, ci, col, hdr_fmt)

    ws.freeze_panes(1, 0)

    for ri, entry in enumerate(ip_summary, start=1):
        for ci, col in enumerate(columns):
            val = entry.get(col, 0)
            if col == "IP Address":
                ws.write(ri, ci, safe_cell_value(val), center_fmt)
            else:
                num_val = int(val) if val else 0
                fmt = center_fmt
                if col in SEVERITY_COLORS and num_val > 0:
                    fmt = sev_fmts.get(col, center_fmt)
                ws.write_number(ri, ci, num_val, fmt)

    ws.set_column(0, 0, 18)
    for ci in range(1, len(columns)):
        ws.set_column(ci, ci, 14)

    logger.info("IP-Summary: %d IPs written", len(ip_summary))


# =============================================================================
# Public API
# =============================================================================

def write_excel_report(
    rows: list[Finding],
    output_path: Union[str, BytesIO],
    include_status: bool = False,
    status_counts: Optional[dict[str, int]] = None,
    previous_severity_counts: Optional[dict[str, int]] = None,
    progress_callback: Optional[Callable[[str, float], None]] = None,
) -> str:
    """
    Write the complete Excel report (Findings + Summary + IP-Summary).

    Args:
        rows:                     Processed list of Finding dicts.
        output_path:              File path or BytesIO for testing.
        include_status:           True for rescan mode.
        status_counts:            Status counts (rescan only).
        previous_severity_counts: Previous scan counts (rescan only).
        progress_callback:        Optional (message, pct) callback.

    Returns:
        The output_path string on success.

    Raises:
        ExcelWriterError on any write failure.
    """
    from core.csv_processor import get_severity_counts, get_ip_summary

    try:
        if progress_callback:
            progress_callback("Creating Excel workbook...", 70)

        wb = xlsxwriter.Workbook(
            output_path,
            {"constant_memory": True, "strings_to_urls": False},
        )

        # --- Filter rows for the Findings sheet (exclude Informational & Low) ---
        findings_rows = [
            r for r in rows
            if r.get("Severity", "").lower() not in ("informational", "low")
        ]
        excluded = len(rows) - len(findings_rows)
        if excluded:
            logger.warning(
                "Findings sheet: excluded %d Low/Informational rows "
                "(full count: %d, written: %d)",
                excluded, len(rows), len(findings_rows),
            )
        else:
            logger.info("Full findings: %d | Findings sheet: %d",
                         len(rows), len(findings_rows))

        # --- Determine which rows feed into Summary & IP-Summary ---
        # In rescan mode, only New + Open findings count toward severity
        # totals and the IP-Summary.  Resolved findings appear on the
        # Findings sheet but must NOT inflate counts.
        if include_status:
            active_rows = [
                r for r in rows
                if r.get("Status", "").strip().lower() not in ("resolved",)
            ]
            logger.info(
                "Rescan mode: %d active (New/Open), %d Resolved excluded "
                "from Summary & IP-Summary",
                len(active_rows), len(rows) - len(active_rows),
            )
        else:
            active_rows = rows

        all_severity_counts = get_severity_counts(active_rows)

        # Unique IPs (from ALL rows — Resolved IPs still appear in header)
        ip_key = "IP Address" if rows and "IP Address" in rows[0] else "ip_address"
        unique_ips = sorted({r.get(ip_key, "") for r in rows if r.get(ip_key, "")})

        # 1. Findings sheet (includes Resolved rows so users can see them)
        _write_findings_sheet(wb, findings_rows, include_status, progress_callback)

        # 2. Summary sheet
        if include_status and previous_severity_counts:
            # Compute per-severity breakdowns by status for the 4-column summary.
            from config import SEVERITY_ORDER as _sev_order
            sev_key = "Severity" if rows and "Severity" in rows[0] else "severity"
            mitigated_counts: dict[str, int] = {s: 0 for s in _sev_order}
            current_scan_counts: dict[str, int] = {s: 0 for s in _sev_order}
            change_counts: dict[str, int] = {s: 0 for s in _sev_order}

            for r in rows:
                sev = r.get(sev_key, "Informational")
                status = r.get("Status", "").strip()
                if status == "Resolved":
                    mitigated_counts[sev] = mitigated_counts.get(sev, 0) + 1
                elif status in ("New", "Open"):
                    current_scan_counts[sev] = current_scan_counts.get(sev, 0) + 1
                    if status == "New":
                        change_counts[sev] = change_counts.get(sev, 0) + 1

            _write_summary_rescan(
                wb, previous_severity_counts,
                mitigated_counts, current_scan_counts, change_counts,
                unique_ips, progress_callback,
            )
        else:
            _write_summary_new(wb, all_severity_counts, unique_ips, progress_callback)

        # 3. IP-Summary sheet (uses active_rows: New + Open only in rescan)
        ip_summary = get_ip_summary(active_rows)
        _write_ip_summary_sheet(wb, ip_summary, progress_callback)

        # Finalize
        if progress_callback:
            progress_callback("Saving Excel file...", 98)

        wb.close()

        if progress_callback:
            progress_callback("Report generated successfully!", 100)

        logger.info("Excel report saved to: %s", output_path)
        return str(output_path)

    except PermissionError:
        raise ExcelWriterError(
            "Cannot save Excel file",
            f"Permission denied. The file may be open: {output_path}",
        )
    except OSError as exc:
        if "no space" in str(exc).lower() or "disk" in str(exc).lower():
            raise ExcelWriterError("Cannot save Excel file", "Insufficient disk space.")
        raise ExcelWriterError("Cannot save Excel file", str(exc))
    except Exception as exc:
        logger.exception("Error writing Excel file")
        raise ExcelWriterError("Error creating Excel report", str(exc))
