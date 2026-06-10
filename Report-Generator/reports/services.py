"""
Service layer for the Reports app.

This module bridges Django HTTP uploads to the existing pure-Python core logic.
The core modules (csv_processor, excel_writer, rescan_comparer) remain untouched;
this layer handles only:
  1. Saving uploaded files to temp paths for core ingestion.
  2. Invoking the processing pipeline.
  3. Writing Excel output to a BytesIO for HTTP streaming.
  4. Cleaning up temp files.

This design keeps all business logic in `core/` and ensures Django views
remain thin controllers.
"""

import logging
import os
import tempfile
from io import BytesIO
from pathlib import Path
from typing import Optional

from django.core.files.uploadedfile import UploadedFile

from core.csv_processor import process_csv_files, CSVProcessingError
from core.excel_writer import write_excel_report, ExcelWriterError
from core.rescan_comparer import process_rescan, RescanCompareError

logger = logging.getLogger(__name__)


class ReportGenerationError(Exception):
    """Raised when report generation fails at the service layer."""

    def __init__(self, message: str, details: str = "") -> None:
        self.message = message
        self.details = details
        super().__init__(message)


def _save_upload_to_temp(upload: UploadedFile, suffix: str = ".csv") -> str:
    """
    Save a Django UploadedFile to a named temporary file.

    Returns the absolute path to the temp file.  Caller is responsible
    for cleanup (see _cleanup_temps).
    """
    fd, path = tempfile.mkstemp(suffix=suffix, prefix="nessus_")
    try:
        with os.fdopen(fd, "wb") as fh:
            for chunk in upload.chunks():
                fh.write(chunk)
    except Exception:
        os.unlink(path)
        raise
    logger.debug("Saved upload '%s' to temp: %s", upload.name, path)
    return path


def _cleanup_temps(paths: list[str]) -> None:
    """Best-effort removal of temporary files."""
    for p in paths:
        try:
            if os.path.exists(p):
                os.unlink(p)
                logger.debug("Cleaned up temp: %s", p)
        except OSError as exc:
            logger.warning("Failed to clean temp %s: %s", p, exc)


def generate_new_report(csv_uploads: list[UploadedFile]) -> BytesIO:
    """
    Process uploaded CSV files and return an in-memory Excel workbook.

    Args:
        csv_uploads: List of Django UploadedFile objects (.csv).

    Returns:
        BytesIO containing the .xlsx workbook bytes.

    Raises:
        ReportGenerationError on any failure.
    """
    if not csv_uploads:
        raise ReportGenerationError("No files provided", "Please upload at least one CSV file.")

    temp_paths: list[str] = []
    try:
        # 1. Save uploads to temp files (core expects file paths)
        for upload in csv_uploads:
            temp_paths.append(_save_upload_to_temp(upload, suffix=".csv"))

        # 2. Run the core processing pipeline (normalize → omit → dedup → sort)
        rows = process_csv_files(filepaths=temp_paths)

        # 3. Write Excel to in-memory buffer
        output = BytesIO()
        write_excel_report(rows, output, include_status=False)
        output.seek(0)
        return output

    except (CSVProcessingError, ExcelWriterError) as exc:
        logger.error("Report generation failed: %s", exc)
        raise ReportGenerationError(str(exc), getattr(exc, "details", ""))

    except Exception as exc:
        logger.exception("Unexpected error during report generation")
        raise ReportGenerationError(
            "An unexpected error occurred",
            str(exc),
        )

    finally:
        _cleanup_temps(temp_paths)


def generate_rescan_report(
    csv_uploads: list[UploadedFile],
    previous_upload: UploadedFile,
) -> BytesIO:
    """
    Process uploaded CSVs against a previous Excel report for rescan comparison.

    Args:
        csv_uploads:     List of new CSV uploads.
        previous_upload: The previous .xlsx report to compare against.

    Returns:
        BytesIO containing the rescan .xlsx workbook bytes.

    Raises:
        ReportGenerationError on any failure.
    """
    if not csv_uploads:
        raise ReportGenerationError("No CSV files", "Please upload at least one CSV file.")
    if not previous_upload:
        raise ReportGenerationError("No previous report", "Please upload the previous Excel report.")

    temp_paths: list[str] = []
    prev_path: Optional[str] = None

    try:
        # 1. Save CSV uploads
        for upload in csv_uploads:
            temp_paths.append(_save_upload_to_temp(upload, suffix=".csv"))

        # 2. Save previous Excel report
        prev_path = _save_upload_to_temp(previous_upload, suffix=".xlsx")

        # 3. Process current CSVs
        current_rows = process_csv_files(filepaths=temp_paths)

        # 4. Compare against previous report
        merged, status_counts, prev_sev_counts = process_rescan(
            current_rows, prev_path,
        )

        # 5. Write Excel
        output = BytesIO()
        write_excel_report(
            merged,
            output,
            include_status=True,
            status_counts=status_counts,
            previous_severity_counts=prev_sev_counts,
        )
        output.seek(0)
        return output

    except (CSVProcessingError, ExcelWriterError, RescanCompareError) as exc:
        logger.error("Rescan report generation failed: %s", exc)
        raise ReportGenerationError(str(exc), getattr(exc, "details", ""))

    except Exception as exc:
        logger.exception("Unexpected error during rescan generation")
        raise ReportGenerationError(
            "An unexpected error occurred",
            str(exc),
        )

    finally:
        all_temps = temp_paths + ([prev_path] if prev_path else [])
        _cleanup_temps(all_temps)
