"""
WSGI config for the VAPT Platform.
"""

import os
from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "vapt_platform.settings")
application = get_wsgi_application()
