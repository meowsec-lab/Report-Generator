"""
Root URL configuration for the VAPT Platform.

Routes:
    /           → Reports app (main interface)
"""

# pyrefly: ignore [missing-import]
from django.urls import include, path

from django.http import HttpResponse

def system_dashboard(request):
    html = """
    {% extends "reports/base.html" %}
    {% block title %}System Dashboard — VAPT Platform{% endblock %}
    {% block content %}
    <div style="display: flex; flex-direction: column; align-items: center; justify-content: center; height: 60vh; text-align: center;">
        <h1 style="font-size: 2.5rem; font-weight: 700; margin-bottom: 20px; color: var(--accent-primary);">System Dashboard</h1>
        <p style="font-size: 1.2rem; color: var(--text-secondary); max-width: 600px; font-style: italic;">
            "The quietest people have the loudest minds." <br>— Stephen Hawking
        </p>
        <p style="font-size: 1.2rem; color: var(--text-secondary); max-width: 600px; font-style: italic; margin-top: 20px;">
            "Security is not a product, but a process." <br>— Bruce Schneier
        </p>
        <div style="margin-top: 40px; padding: 20px; border: 1px solid var(--border-default); border-radius: var(--radius-md); background: var(--bg-surface);">
            <p style="color: var(--text-muted); font-size: 0.9rem;">(Global system metrics will be developed here in the future.)</p>
        </div>
    </div>
    {% endblock %}
    """
    from django.template import Engine, Context
    template = Engine.get_default().from_string(html)
    return HttpResponse(template.render(Context({'active_page': 'index'})))

urlpatterns = [
    path("", system_dashboard, name="system_dashboard"),
    path("reports/", include("reports.urls")),
]
