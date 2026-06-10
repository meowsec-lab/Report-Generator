"""
URL routes for the Reports app.

Routes:
    /                → Landing page with both modes
    /new-report/     → Generate a new report from CSV uploads
    /rescan/         → Generate a rescan comparison report
    /download/<name> → Download a generated report file
"""

# pyrefly: ignore [missing-import]
from django.urls import path
from reports import views

app_name = "reports"

urlpatterns = [
    path("new-report/", views.new_report, name="new_report"),
    path("rescan/", views.rescan_report, name="rescan_report"),
    path("download/<str:filename>/", views.download_report, name="download_report"),
]
