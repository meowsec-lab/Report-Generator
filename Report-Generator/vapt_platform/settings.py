"""
Django settings for the VAPT Platform (Nessus Report Generator).

Minimal, production-aware configuration. Uses SQLite by default (no
external services required). Static files are served via WhiteNoise
in production.
"""

import os
import sys
from pathlib import Path

# =============================================================================
# PATHS
# =============================================================================

BASE_DIR = Path(__file__).resolve().parent.parent

# Ensure project root is on sys.path so existing core modules can do
# `from config import ...` without modification.
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# =============================================================================
# SECURITY
# =============================================================================

SECRET_KEY = os.environ.get(
    "DJANGO_SECRET_KEY",
    "django-insecure-dev-only-change-me-in-production-abc123xyz",
)

DEBUG = os.environ.get("DJANGO_DEBUG", "True").lower() in ("true", "1", "yes")

ALLOWED_HOSTS = os.environ.get("DJANGO_ALLOWED_HOSTS", "*").split(",")

# =============================================================================
# APPLICATIONS
# =============================================================================

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.staticfiles",
    "reports",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
]

ROOT_URLCONF = "vapt_platform.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
            ],
        },
    },
]

WSGI_APPLICATION = "vapt_platform.wsgi.application"

# =============================================================================
# DATABASE (SQLite — no setup required)
# =============================================================================

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

# =============================================================================
# STATIC FILES
# =============================================================================

STATIC_URL = "/static/"
STATICFILES_DIRS = []
STATIC_ROOT = BASE_DIR / "staticfiles"

# =============================================================================
# FILE UPLOADS
# =============================================================================

# Max upload size: 256 MB (Nessus CSVs can be large)
DATA_UPLOAD_MAX_MEMORY_SIZE = 268435456
FILE_UPLOAD_MAX_MEMORY_SIZE = 268435456

# Temp directory for uploaded files during processing
MEDIA_ROOT = BASE_DIR / "media"
MEDIA_URL = "/media/"

# =============================================================================
# LOGGING
# =============================================================================

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "%(asctime)s %(name)s %(levelname)s %(message)s",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        },
    },
    "root": {
        "handlers": ["console"],
        "level": "INFO",
    },
    "loggers": {
        "core": {"level": "DEBUG", "propagate": True},
        "reports": {"level": "DEBUG", "propagate": True},
    },
}

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
