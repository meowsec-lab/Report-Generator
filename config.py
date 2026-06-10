"""
Configuration constants for the Nessus Report Generator.

OMISSION LOGIC (applied to every CSV row):
──────────────────────────────────────────
1. ALWAYS_OMIT — plugin names that are unconditionally removed.
2. SELF_SIGNED_PLUGINS — a subset of SSL/TLS certificate plugins that are
   removed UNLESS the Host IP belongs to the 192.168.195.0/24 subnet.

Matching is case-insensitive and whitespace-stripped.

Contains column mappings, color definitions, and default values.
"""

import ipaddress

# =============================================================================
# PLUGIN OMISSION RULES
# =============================================================================

# Plugins that are ALWAYS removed from the report (case-insensitive).
# NOTE: SELF_SIGNED_PLUGINS are handled separately — they get a subnet exception.
ALWAYS_OMIT: frozenset[str] = frozenset({
    "ssl certificate validity - duration",
    "ssl certificate expiry",
    "weblogic ssl certificate chain user spoofing",
    "ssl expired certificate detection",
    "ssl insecure protocols",
})

# Plugins related to self-signed / untrusted certificates.
# These are omitted UNLESS the host IP is in SUBNET_EXEMPTION.
SELF_SIGNED_PLUGINS: frozenset[str] = frozenset({
    "ssl certificate cannot be trusted",
    "ssl certificate with wrong hostname",
    "ssl self-signed certificate",
    "ssl/tls self-signed certificate",
    "ssl/tls certificate common name mismatch",
})

# If a self-signed plugin's Host IP falls inside this subnet, KEEP the row.
SUBNET_EXEMPTION: ipaddress.IPv4Network = ipaddress.ip_network("192.168.195.0/24")

# Characters that trigger Excel formula injection — prefix with ' if found at start.
FORMULA_INJECTION_CHARS: frozenset[str] = frozenset({"=", "+", "-", "@"})

# Maximum Excel worksheet name length (Excel spec).
MAX_SHEET_NAME_LENGTH: int = 31

# Characters forbidden in Excel worksheet names.
INVALID_SHEET_NAME_CHARS: str = r"[]:*?/\\"

# =============================================================================
# COLUMN NAME MAPPINGS
# =============================================================================
# Maps various possible column names (lowercase) to standardized internal names.
# Order matters — first match wins.

COLUMN_MAPPINGS: dict[str, list[str]] = {
    "ip_address": [
        "ip address", "host", "ip", "target", "asset", "hostname", "host ip"
    ],
    "plugin_name": [
        "plugin name", "name", "issue name", "vulnerability", "finding",
        "title", "plugin", "vuln name"
    ],
    "severity": [
        "severity", "risk", "risk factor", "risk level", "criticality"
    ],
    "port": [
        "port", "port number", "service port", "tcp port", "udp port"
    ],
    "protocol": [
        "protocol", "proto", "service protocol"
    ],
    "plugin_id": [
        "plugin id", "pluginid", "id", "vulnerability id", "vuln id"
    ],
    "synopsis": [
        "synopsis", "summary", "brief", "short description"
    ],
    "description": [
        "description", "details", "detail", "full description", "desc"
    ],
    "solution": [
        "solution", "steps to remediate", "remediation", "fix", "recommendation", "mitigation"
    ],
    "plugin_output": [
        "plugin output", "output", "evidence", "proof", "result", "findings"
    ],
    "cvss_v3_base_score": [
        "cvss v3.0 base score", "cvss v3 base score", "cvss3 base score",
        "cvss v3.1 base score", "cvss3", "cvssv3"
    ],
    "cvss_v2_base_score": [
        "cvss v2.0 base score", "cvss v2 base score", "cvss2 base score",
        "cvss base score", "cvss2", "cvssv2", "cvss"
    ],
    "cve": [
        "cve", "cve id", "cve-id", "cves", "cve number"
    ],
    "see_also": [
        "see also", "references", "reference", "links", "urls"
    ],
    "first_discovered": [
        "first discovered", "first seen", "discovered", "detection date"
    ],
    "last_observed": [
        "last observed", "last seen", "last detected"
    ],
    "vpr": [
        "vulnerability priority rating", "vpr"
    ],
    "epss": [
        "exploit prediction scoring system (epss)", "exploit prediction system (epss)", "epss"
    ]
}

# =============================================================================
# OUTPUT COLUMNS (in exact order per spec)
# =============================================================================

# Columns for NEW REPORT (in order):
OUTPUT_COLUMNS_NEW: list[str] = [
    "Serial",
    "IP Address",
    "Issue Name",          # From Plugin Name
    "Severity",
    "Vulnerability Priority Rating",
    "Exploit Prediction System (EPSS)",
    "Description",         # From Synopsis
    "Impact",              # From Description
    "Steps to Remediate",  # From Solution
    "Port",
    "Protocol",
    "CVE",
    "Plugin Output",
    "See Also"
]

# Columns for RESCAN (in order):
OUTPUT_COLUMNS_RESCAN: list[str] = [
    "Serial",
    "IP Address",
    "Issue Name",
    "Severity",
    "Status",
    "Vulnerability Priority Rating",
    "Exploit Prediction System (EPSS)",
    "Description",
    "Impact",
    "Steps to Remediate",
    "Port",
    "Protocol",
    "CVE",
    "Plugin Output",
    "See Also"
]

# Column renaming for output (internal_name -> display_name)
COLUMN_RENAMES: dict[str, str] = {
    "plugin_name": "Issue Name",
    "synopsis": "Description",
    "description": "Impact",
    "solution": "Steps to Remediate",
    "ip_address": "IP Address",
    "port": "Port",
    "protocol": "Protocol",
    "plugin_id": "Plugin ID",
    "severity": "Severity",
    "plugin_output": "Plugin Output",
    "cve": "CVE",
    "cvss_v3_base_score": "CVSS v3 Base Score",
    "cvss_v2_base_score": "CVSS v2 Base Score",
    "see_also": "See Also",
    "vpr": "Vulnerability Priority Rating",
    "epss": "Exploit Prediction System (EPSS)"
}

# =============================================================================
# SEVERITY DEFINITIONS
# =============================================================================

# CVSS score ranges for severity derivation
CVSS_SEVERITY_RANGES: dict[str, tuple[float, float]] = {
    "Critical": (9.0, 10.0),
    "High": (7.0, 8.9),
    "Medium": (4.0, 6.9),
    "Low": (0.1, 3.9),
    "Informational": (0.0, 0.0)
}

# Text variations for severity normalization (lowercase -> standard)
SEVERITY_NORMALIZATION: dict[str, str] = {
    # Critical
    "critical": "Critical",
    "crit": "Critical",
    "4": "Critical",
    # High
    "high": "High",
    "3": "High",
    # Medium
    "medium": "Medium",
    "med": "Medium",
    "moderate": "Medium",
    "2": "Medium",
    # Low
    "low": "Low",
    "1": "Low",
    # Informational
    "informational": "Informational",
    "info": "Informational",
    "none": "Informational",
    "0": "Informational",
    "": "Informational"
}

# Severity sort order (for sorting findings)
SEVERITY_ORDER: dict[str, int] = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Informational": 4
}

# =============================================================================
# EXCEL FORMATTING - COLORS (hex format for xlsxwriter)
# =============================================================================

# Header styling — DARK RED as specified
HEADER_BG_COLOR: str = "#8B0000"         # Dark Red
HEADER_FONT_COLOR: str = "#FFFFFF"       # White bold text

# Severity background colors (for severity column cells)
SEVERITY_COLORS: dict[str, str] = {
    "Critical": "#8B0000",         # Dark Red
    "High": "#FF0000",             # Red
    "Medium": "#FFA500",           # Orange
    "Low": "#87CEEB",              # Light Blue
    "Informational": "#FFFFFF"     # White
}

# Severity font colors (for contrast)
SEVERITY_FONT_COLORS: dict[str, str] = {
    "Critical": "#FFFFFF",         # White (bold)
    "High": "#FFFFFF",             # White (bold)
    "Medium": "#000000",           # Black (bold)
    "Low": "#000000",              # Black (bold)
    "Informational": "#000000"     # Black
}

# Status TEXT colors for rescan mode
STATUS_FONT_COLORS: dict[str, str] = {
    "Open": "#FF0000",             # Red text
    "Resolved": "#00B050",         # Green text
    "New": "#0070C0"               # Blue text
}

# =============================================================================
# EXCEL FORMATTING - DIMENSIONS
# =============================================================================

# Column widths (in characters)
MAX_COLUMN_WIDTH: int = 50
MIN_COLUMN_WIDTH: int = 10

# Specific column width overrides
COLUMN_WIDTHS: dict[str, int] = {
    "Serial": 8,
    "IP Address": 15,
    "Port": 8,
    "Protocol": 10,
    "Issue Name": 60,
    "Severity": 12,
    "Status": 10,
    "Description": 60,
    "Impact": 60,
    "Steps to Remediate": 60,
    "Plugin Output": 50,
    "CVE": 20,
    "See Also": 40,
    "Vulnerability Priority Rating": 30,
    "Exploit Prediction System (EPSS)": 35
}

# Row height
DEFAULT_ROW_HEIGHT: int = 15
HEADER_ROW_HEIGHT: int = 20

# =============================================================================
# FILE HANDLING
# =============================================================================

# Encoding fallback order for CSV reading
ENCODING_FALLBACK: list[str] = ["utf-8-sig", "utf-8", "cp1252", "latin1", "iso-8859-1"]

# Invalid filename characters (Windows)
INVALID_FILENAME_CHARS: list[str] = ['/', '\\', ':', '*', '?', '"', '<', '>', '|']

# Maximum filename length
MAX_FILENAME_LENGTH: int = 100

# =============================================================================
# DEDUPLICATION & MATCHING
# =============================================================================

# Columns used for identifying duplicate findings (internal names)
DEDUP_KEYS: list[str] = ["ip_address", "plugin_name", "port"]

# Columns used for matching in rescan comparison
RESCAN_MATCH_COLUMNS: list[str] = ["Issue Name", "IP Address", "Port"]

# =============================================================================
# PROGRESS REPORTING
# =============================================================================

PROGRESS_STEPS: dict[str, tuple[int, int]] = {
    "reading_files": (0, 40),
    "consolidating": (40, 50),
    "deduplicating": (50, 60),
    "sorting": (60, 70),
    "writing_excel": (70, 100)
}

# =============================================================================
# APPLICATION SETTINGS
# =============================================================================

APP_NAME: str = "Nessus Report Generator"
APP_VERSION: str = "3.0.0"
WINDOW_WIDTH: int = 800
WINDOW_HEIGHT: int = 850
