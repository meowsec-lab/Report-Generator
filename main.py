#!/usr/bin/env python
"""
Nessus Report Generator — Entry Point.

Launches the Django web application.

Usage:
    python main.py                    # Start dev server (http://127.0.0.1:8000)
    python main.py runserver 0:8080   # Custom host/port
    python main.py --help             # All Django management commands

This file is equivalent to Django's manage.py but named main.py
so `python main.py` works as the single entry point.
"""

import os
import sys


def main() -> None:
    """Run Django management commands."""
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "vapt_platform.settings")
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?\n"
            "Install dependencies: pip install -r requirements.txt"
        ) from exc

    # Default to 'runserver' if no command is provided
    if len(sys.argv) == 1:
        sys.argv.append("runserver")

    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
