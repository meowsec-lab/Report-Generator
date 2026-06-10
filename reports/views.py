"""
Views for the Reports app.

These are intentionally thin controllers.  All business logic lives in
reports.services (which delegates to core/).
"""

import logging
from datetime import datetime

from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import render

from reports.services import (
    ReportGenerationError,
    generate_new_report,
    generate_rescan_report,
)

logger = logging.getLogger(__name__)


def new_report(request: HttpRequest) -> HttpResponse:
    """
    POST: Accept CSV uploads, generate an Excel report, and stream it back.
    GET:  Show the new-report form.
    """
    if request.method != "POST":
        return render(request, "reports/new_report.html", {"active_page": "new_report"})

    csv_files = request.FILES.getlist("csv_files")
    output_name = request.POST.get("output_name", "").strip()

    if not csv_files:
        return render(request, "reports/new_report.html", {
            "error": "Please select at least one CSV file.",
            "active_page": "new_report",
        })

    if not output_name:
        output_name = f"Nessus_Report_{datetime.now():%Y%m%d_%H%M%S}"

    if not output_name.lower().endswith(".xlsx"):
        output_name += ".xlsx"

    try:
        excel_buffer = generate_new_report(csv_files)

        response = HttpResponse(
            excel_buffer.getvalue(),
            content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
        response["Content-Disposition"] = f'attachment; filename="{output_name}"'
        return response

    except ReportGenerationError as exc:
        logger.error("New report failed: %s — %s", exc.message, exc.details)
        return render(request, "reports/new_report.html", {
            "error": exc.message,
            "details": exc.details,
            "active_page": "new_report",
        })


def rescan_report(request: HttpRequest) -> HttpResponse:
    """
    POST: Accept CSV + previous Excel uploads, generate rescan report.
    GET:  Show the rescan form.
    """
    if request.method != "POST":
        return render(request, "reports/rescan.html", {"active_page": "rescan"})

    csv_files = request.FILES.getlist("csv_files")
    previous_file = request.FILES.get("previous_report")
    output_name = request.POST.get("output_name", "").strip()

    errors = []
    if not csv_files:
        errors.append("Please select at least one CSV file.")
    if not previous_file:
        errors.append("Please upload the previous Excel report.")

    if errors:
        return render(request, "reports/rescan.html", {
            "error": " ".join(errors),
            "active_page": "rescan",
        })

    if not output_name:
        output_name = f"Nessus_Rescan_{datetime.now():%Y%m%d_%H%M%S}"

    if not output_name.lower().endswith(".xlsx"):
        output_name += ".xlsx"

    try:
        excel_buffer = generate_rescan_report(csv_files, previous_file)

        response = HttpResponse(
            excel_buffer.getvalue(),
            content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
        response["Content-Disposition"] = f'attachment; filename="{output_name}"'
        return response

    except ReportGenerationError as exc:
        logger.error("Rescan report failed: %s — %s", exc.message, exc.details)
        return render(request, "reports/rescan.html", {
            "error": exc.message,
            "details": exc.details,
            "active_page": "rescan",
        })


def download_report(request: HttpRequest, filename: str) -> HttpResponse:
    """Placeholder for future stored-report downloads."""
    return JsonResponse(
        {"error": "Report storage is not yet implemented. Reports are returned directly after generation."},
        status=501,
    )
