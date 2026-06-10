# CONTEXT.md — Reports App (Nessus Report Generator)

> **Purpose**: This document is the authoritative reference for all business logic,
> data flows, and architectural decisions specifically related to the `reports` app.
> Read this before modifying any code within the `reports` feature.
> It exists so that both human developers and AI agents can understand, debug,
> and extend the reports functionality without re-reading the entire codebase.

---

## 1. Project Structure

```
Report-Generator/
├── main.py                          # Entry point — runs Django dev server
├── config.py                        # ALL business rules, mappings, constants
├── requirements.txt                 # Python dependencies
├── vapt_platform/                   # Django project settings
│   ├── settings.py                  # Django config (DB, static, uploads)
│   ├── urls.py                      # Root URL router → reports app
│   └── wsgi.py                      # WSGI entry point
├── reports/                         # Django app (self-contained)
│   ├── urls.py                      # App URL routes
│   ├── views.py                     # HTTP handlers (thin controllers)
│   ├── services.py                  # Bridge: Django uploads → core logic
│   ├── templates/reports/           # HTML templates
│   │   ├── base.html                # Layout with sidebar
│   │   ├── index.html               # Dashboard landing page
│   │   ├── new_report.html          # New Report form
│   │   └── rescan.html              # Rescan Comparison form
│   └── static/css/style.css         # UI styles
├── core/                            # Pure-Python business logic (no Django imports)
│   ├── csv_processor.py             # CSV ingestion, normalization, filtering
│   ├── excel_writer.py              # Excel generation (xlsxwriter)
│   ├── rescan_comparer.py           # Rescan status assignment (New/Open/Resolved)
│   └── validators.py                # File/path validation helpers
├── test_core.py                     # Unit + integration tests (pytest)
└── sample_data/                     # Sample CSV/Excel for testing
```

### Key Architectural Principle
The `core/` package contains **zero Django imports**. It accepts file paths and
returns Python objects. The `reports/services.py` layer is the only place where
Django upload objects are converted to file paths that `core/` understands. This
means:
- Core logic can be tested independently (no Django test client needed).
- Core logic can be reused in CLI tools, background workers, or other frameworks.
- Django views remain thin (< 30 lines each).

---

## 2. Data Flow — New Report Mode

```
User uploads CSVs via browser
         │
         ▼
  reports/views.py::new_report()          ← HTTP handler
         │
         ▼
  reports/services.py::generate_new_report()
         │
         ├─ Save each upload to a temp file (NamedTemporaryFile)
         │
         ▼
  core/csv_processor.py::process_csv_files()   ← MAIN PIPELINE
         │
         ├─ 1. READ: read_csv_rows() per file
         │      └─ Encoding: chardet → utf-8-sig → utf-8 → cp1252 → latin1 → iso-8859-1
         │      └─ Last resort: utf-8 with replacement chars
         │
         ├─ 2. NORMALIZE: normalize_row() per row
         │      └─ Maps CSV headers to internal names via config.COLUMN_MAPPINGS
         │      └─ Severity collision: text labels beat numeric codes
         │
         ├─ 3. OMIT: apply_omission_rules()
         │      └─ Tier 1: ALWAYS_OMIT (unconditional blocklist)
         │      └─ Tier 2: SELF_SIGNED_PLUGINS (omit UNLESS IP is in 192.168.195.0/24)
         │
         ├─ 4. DERIVE SEVERITY: derive_severity() per row
         │      └─ Priority: text severity → CVSS v3 → CVSS v2 → "Informational"
         │
         ├─ 5. DEDUPLICATE: remove_duplicates()
         │      └─ Key: ip_address | plugin_name | port (lowercased)
         │      └─ First occurrence kept
         │
         ├─ 6. SORT: sort_by_severity()
         │      └─ Primary: severity (Critical=0 → Informational=4)
         │      └─ Secondary: IP address (alphabetical)
         │
         └─ 7. RENAME & ENSURE: rename_for_output(), ensure_output_columns()
                └─ Internal names → Display names (e.g., plugin_name → "Issue Name")
                └─ Missing output columns filled with empty string
         │
         ▼
  core/excel_writer.py::write_excel_report()
         │
         ├─ FILTER: Exclude Low & Informational from Findings sheet
         │
         ├─ Sheet 1: "Findings" — main data with severity color-coding
         ├─ Sheet 2: "Summary"  — severity count table
         └─ Sheet 3: "IP-Summary" — per-IP severity breakdown
         │
         ▼
  BytesIO → HTTP Response (file download)
  Temp files cleaned up
```

---

## 3. Data Flow — Rescan Comparison Mode

```
User uploads new CSVs + previous .xlsx report
         │
         ▼
  reports/services.py::generate_rescan_report()
         │
         ├─ Save uploads to temp files
         │
         ├─ Run process_csv_files() on new CSVs    (same pipeline as New Report)
         │
         ▼
  core/rescan_comparer.py::process_rescan()
         │
         ├─ 1. LOAD PREVIOUS: _load_previous_excel()
         │      └─ Opens .xlsx with openpyxl (read_only mode)
         │      └─ Reads the "Findings" sheet into Finding dicts
         │
         ├─ 2. BUILD KEYS: _finding_key(row)
         │      └─ Key format: "ip|issue_name|port" (lowercased, stripped)
         │
         ├─ 3. COMPARE: _compare_findings()
         │      ├─ New     = current_keys − previous_keys
         │      ├─ Open    = current_keys ∩ previous_keys
         │      └─ Resolved = previous_keys − current_keys
         │
         ├─ 4. ASSIGN STATUS to each current row
         │
         ├─ 5. BUILD RESOLVED ROWS from previous data
         │      └─ Plugin Output replaced with "[Remediated - No longer detected]"
         │
         ├─ 6. MERGE: current rows + resolved rows
         │
         └─ 7. SORT: Status (New→Open→Resolved) then Severity
         │
         ▼
  core/excel_writer.py::write_excel_report(include_status=True)
         │
         ├─ Sheet 1: "Findings" — includes Status column + color coding
         │      └─ New (blue), Open (red), Resolved (green) font colors
         │
         ├─ Sheet 2: "Summary" — 4-column rescan breakdown
         │      ├─ Previous Scan: severity counts from old report
         │      ├─ Mitigated: Resolved-status count per severity
         │      ├─ Current Scan: New+Open count per severity
         │      └─ Change: New-only count per severity
         │
         └─ Sheet 3: "IP-Summary" — only active (New+Open) findings per IP
```

---

## 4. Omission Engine — Detailed Rules

The omission engine runs on **every row** before severity derivation. It is
defined in `config.py` and executed in `core/csv_processor.py::should_omit_row()`.

### Tier 1: Absolute Blocklist (`config.ALWAYS_OMIT`)

These plugins are **always removed**, regardless of host IP:

| Plugin Name (case-insensitive)                  |
|-------------------------------------------------|
| ssl certificate validity - duration             |
| ssl certificate expiry                          |
| weblogic ssl certificate chain user spoofing    |
| ssl expired certificate detection               |
| ssl insecure protocols                          |

### Tier 2: Conditional Blocklist (`config.SELF_SIGNED_PLUGINS`)

These SSL certificate plugins are removed **UNLESS** the host IP belongs to
the exempt subnet `192.168.195.0/24`:

| Plugin Name (case-insensitive)                  |
|-------------------------------------------------|
| ssl certificate cannot be trusted               |
| ssl certificate with wrong hostname             |
| ssl self-signed certificate                     |
| ssl/tls self-signed certificate                 |
| ssl/tls certificate common name mismatch        |

**Exemption check** (`ip_in_subnet()`): Uses Python's `ipaddress` module.
Returns `False` for hostnames, empty strings, or invalid IPs — meaning those
rows are omitted.

### How to Modify

- **Add a new always-omitted plugin**: Add its name (lowercase) to `config.ALWAYS_OMIT`.
- **Add a new conditional plugin**: Add to `config.SELF_SIGNED_PLUGINS`.
- **Change the exempt subnet**: Modify `config.SUBNET_EXEMPTION` CIDR.

---

## 5. Severity System — Detailed Rules

### 5.1. Normalization Priority

Implemented in `core/csv_processor.py::derive_severity()`:

1. **Text severity** (from the `severity` column) — if it's a recognized label,
   use it directly. This is authoritative.
2. **CVSS v3 Base Score** — if no text severity, derive from score.
3. **CVSS v2 Base Score** — if no CVSS v3, derive from v2.
4. **Default** — "Informational" if everything is missing.

### 5.2. Text → Standard Mapping (`config.SEVERITY_NORMALIZATION`)

| Raw Value (case-insensitive) | Standard Label  |
|------------------------------|-----------------|
| critical, crit, 4            | Critical        |
| high, 3                      | High            |
| medium, med, moderate, 2     | Medium          |
| low, 1                       | Low             |
| informational, info, none, 0, (empty) | Informational |

### 5.3. CVSS Score → Severity (`config.CVSS_SEVERITY_RANGES`)

| Score Range | Severity       |
|-------------|----------------|
| 9.0 – 10.0  | Critical       |
| 7.0 – 8.9   | High           |
| 4.0 – 6.9   | Medium         |
| 0.1 – 3.9   | Low            |
| 0.0          | Informational  |
| > 10.0       | Critical (clamped) |

### 5.4. Column Collision: Text vs. Numeric Severity

**Background**: Some Nessus CSV exports have both a `Risk` column (text: "High")
and a `Severity` column (numeric: "2"). Both map to the internal `severity` key.

**Rule** (in `normalize_row()`):
- If multiple columns map to `severity`, the **text label wins** over a numeric code.
- For all other column collisions, last value wins.
- Known text labels: `critical, crit, high, medium, med, moderate, low, informational, info, none`.

**Regression context**: This was added to fix the SWEET32 vulnerability bug where
"High" was being overwritten by "2" (Medium), causing incorrect reporting.

---

## 6. Column Mapping System

### 6.1. Input Mapping (`config.COLUMN_MAPPINGS`)

Maps raw CSV headers (case-insensitive, whitespace-stripped) to internal names.
First match wins.

| Internal Name       | Accepted CSV Headers                                             |
|---------------------|------------------------------------------------------------------|
| `ip_address`        | ip address, host, ip, target, asset, hostname, host ip           |
| `plugin_name`       | plugin name, name, issue name, vulnerability, finding, title, plugin, vuln name |
| `severity`          | severity, risk, risk factor, risk level, criticality             |
| `port`              | port, port number, service port, tcp port, udp port              |
| `protocol`          | protocol, proto, service protocol                                |
| `plugin_id`         | plugin id, pluginid, id, vulnerability id, vuln id               |
| `synopsis`          | synopsis, summary, brief, short description                      |
| `description`       | description, details, detail, full description, desc             |
| `solution`          | solution, steps to remediate, remediation, fix, recommendation, mitigation |
| `plugin_output`     | plugin output, output, evidence, proof, result, findings         |
| `cvss_v3_base_score`| cvss v3.0 base score, cvss v3 base score, cvss3 base score, cvss v3.1 base score, cvss3, cvssv3 |
| `cvss_v2_base_score`| cvss v2.0 base score, cvss v2 base score, cvss2 base score, cvss base score, cvss2, cvssv2, cvss |
| `cve`               | cve, cve id, cve-id, cves, cve number                           |
| `see_also`          | see also, references, reference, links, urls                     |
| `first_discovered`  | first discovered, first seen, discovered, detection date         |
| `last_observed`     | last observed, last seen, last detected                          |
| `vpr`               | vulnerability priority rating, vpr                               |
| `epss`              | exploit prediction scoring system (epss), exploit prediction system (epss), epss |

### 6.2. Output Renaming (`config.COLUMN_RENAMES`)

Internal names → Display names for the Excel output:

| Internal          | Display Name                      |
|-------------------|-----------------------------------|
| `plugin_name`     | Issue Name                        |
| `synopsis`        | Description                       |
| `description`     | Impact                            |
| `solution`        | Steps to Remediate                |
| `ip_address`      | IP Address                        |
| `severity`        | Severity                          |
| `vpr`             | Vulnerability Priority Rating     |
| `epss`            | Exploit Prediction System (EPSS)  |

### 6.3. Output Column Order

**New Report** (`config.OUTPUT_COLUMNS_NEW`):
Serial, IP Address, Issue Name, Severity, VPR, EPSS, Description, Impact,
Steps to Remediate, Port, Protocol, CVE, Plugin Output, See Also

**Rescan** (`config.OUTPUT_COLUMNS_RESCAN`):
Same as above but with **Status** inserted after Severity.

---

## 7. Deduplication

- **Key**: `ip_address | plugin_name | port` (all lowercased, whitespace-stripped)
- **Strategy**: First occurrence wins; subsequent duplicates are silently dropped.
- **When it runs**: After omission rules, after severity derivation.
- **Config**: `config.DEDUP_KEYS = ["ip_address", "plugin_name", "port"]`

---

## 8. Excel Output Specifications

### 8.1. Findings Sheet

- **Filtered**: Only `Critical`, `High`, and `Medium` severities are written.
  `Low` and `Informational` are excluded from this sheet.
- **Severity coloring**: Background + font color per severity level.
  - Critical: Dark Red bg, White text
  - High: Red bg, White text
  - Medium: Orange bg, Black text
  - Low: Light Blue bg, Black text
- **Status coloring** (rescan only): Font color only.
  - New: Blue (#0070C0)
  - Open: Red (#FF0000)
  - Resolved: Green (#00B050)
- **Header**: Dark Red (#8B0000) bg, White bold text, frozen row.
- **Serial**: Auto-incremented starting from 1.

### 8.2. Summary Sheet

**Header block** (rows 0–3): Title, Statement of Methodology, IP list, Note.
All are editable placeholders for the user to fill in.

**Severity table** (row 6 onward):

- **New Report mode**: 2 columns — Severity, Count.
- **Rescan mode**: 5 columns — Severity, Previous Scan, Mitigated, Current Scan, Change.
  - **Previous Scan**: Severity counts from the loaded previous Excel report.
  - **Mitigated**: Count of findings with Status = "Resolved", broken down by severity.
  - **Current Scan**: Count of findings with Status = "New" or "Open", per severity.
  - **Change**: Count of findings with Status = "New" only, per severity.

**Grand Total** row at the bottom sums each column.

### 8.3. IP-Summary Sheet

- One row per unique IP address.
- Columns: IP Address, Critical, High, Medium, Low, Informational, Total.
- Sorted by Total (descending).
- In rescan mode, only **active** (New + Open) findings are counted — Resolved
  findings are excluded from the IP-Summary.

### 8.4. Security Protections

- **Formula injection**: Values starting with `=`, `+`, `-`, `@` are prefixed
  with a single quote `'` to prevent Excel from interpreting them as formulas.
- **Sheet name sanitization**: Characters `[ ] : * ? / \` replaced with `_`;
  names truncated to 31 characters (Excel spec limit).

---

## 9. Rescan Comparison — Detailed Logic

### 9.1. Key Construction

```python
key = f"{ip}|{issue_name}|{port}"  # all lowercased, stripped
```

The key is built from display-name columns (`IP Address`, `Issue Name`, `Port`)
for current rows, and from whatever column names exist in the previous Excel
(supporting both internal and display names with fallbacks).

### 9.2. Status Assignment

```
current_keys  = {key for each row in new scan}
previous_keys = {key for each row in old Excel}

New      = current_keys − previous_keys   → exists now, didn't before
Open     = current_keys ∩ previous_keys   → existed before, still exists
Resolved = previous_keys − current_keys   → existed before, gone now
```

### 9.3. Resolved Row Construction

For each Resolved finding:
1. Copy the row data from the previous Excel report.
2. Set `Status = "Resolved"`.
3. Replace `Plugin Output` with `"[Remediated - No longer detected]"`.

### 9.4. Sort Order

Primary: Status (`New=0`, `Open=1`, `Resolved=2`)
Secondary: Severity (`Critical=0` → `Informational=4`)

---

## 10. Service Layer (`reports/services.py`)

The service layer is the **only integration point** between Django and core logic.
It handles:

1. **Temp file lifecycle**: Uploaded Django `UploadedFile` objects → temp files
   on disk → paths passed to core → temp files cleaned up in `finally` block.
2. **Error translation**: Core exceptions (`CSVProcessingError`, `ExcelWriterError`,
   `RescanCompareError`) are caught and re-raised as `ReportGenerationError` for
   uniform handling in views.
3. **Output packaging**: Core writes Excel to a `BytesIO` buffer, which the
   service returns to the view for HTTP streaming.

---

## 11. Configuration Quick Reference (`config.py`)

| Constant                 | Purpose                                    | Modify When...                          |
|--------------------------|--------------------------------------------|-----------------------------------------|
| `ALWAYS_OMIT`            | Plugins to always remove                   | New plugin should be filtered           |
| `SELF_SIGNED_PLUGINS`    | Conditional SSL omissions                  | New SSL plugin needs conditional filter |
| `SUBNET_EXEMPTION`       | IP range that bypasses SSL omission        | Exempt network changes                  |
| `COLUMN_MAPPINGS`        | CSV header → internal name mapping         | Nessus adds new column names            |
| `OUTPUT_COLUMNS_NEW`     | Column order for new-report Excel          | Adding/removing output columns          |
| `OUTPUT_COLUMNS_RESCAN`  | Column order for rescan Excel              | Adding/removing output columns          |
| `COLUMN_RENAMES`         | Internal → display name mapping            | Changing output column labels           |
| `SEVERITY_NORMALIZATION` | Text → standard severity mapping           | New severity text variations            |
| `CVSS_SEVERITY_RANGES`   | Score → severity derivation                | Adjusting severity thresholds           |
| `SEVERITY_COLORS`        | Background colors for severity cells       | Changing Excel color scheme             |
| `STATUS_FONT_COLORS`     | Font colors for status labels              | Changing rescan status colors           |
| `COLUMN_WIDTHS`          | Per-column widths in Excel                 | Adjusting layout                        |
| `DEDUP_KEYS`             | Fields used for duplicate detection        | Changing dedup criteria                 |
| `ENCODING_FALLBACK`      | Encoding attempt order for CSV reading     | Adding encoding support                 |

---

## 12. Adding a New Feature — Step-by-Step Recipes

### Recipe: Add a New Column to the Excel Report

1. **`config.py`**: Add the raw header variation(s) to `COLUMN_MAPPINGS`.
2. **`config.py`**: Add the internal→display name to `COLUMN_RENAMES`.
3. **`config.py`**: Add the display name to `OUTPUT_COLUMNS_NEW` (and `OUTPUT_COLUMNS_RESCAN` if needed) in the desired position.
4. **`config.py`**: Optionally add a width to `COLUMN_WIDTHS`.
5. **No code changes needed** — the pipeline automatically maps, renames, and outputs.
6. **Test**: Run `pytest test_core.py -v`.

### Recipe: Add a New Plugin to the Blocklist

1. **`config.py`**: Add the plugin name (lowercase, stripped) to `ALWAYS_OMIT` or `SELF_SIGNED_PLUGINS`.
2. **Test**: Add a test case in `test_core.py::TestOmissionRules`.

### Recipe: Change the Exempt Subnet

1. **`config.py`**: Modify `SUBNET_EXEMPTION = ipaddress.ip_network("x.x.x.x/xx")`.
2. **Test**: Update subnet boundary tests.

### Recipe: Add a New Django Page/Feature

1. Add view function in `reports/views.py`.
2. Add URL pattern in `reports/urls.py`.
3. Add template in `reports/templates/reports/`.
4. If it needs core processing, add a service function in `reports/services.py`.
5. Never import Django in `core/`.

---

## 13. Known Issues & Historical Bugs

### SWEET32 Severity Overwrite (Fixed)

**Bug**: The "SWEET32" vulnerability had `Risk: High` and `Severity: 2` in the CSV.
Both columns mapped to `severity`. The numeric "2" (Medium) was overwriting the
authoritative text "High".

**Fix**: `normalize_row()` now checks if the collision is on the `severity` key
and prefers text labels over numeric codes. See `_SEVERITY_TEXT_LABELS` frozenset.

**Tests**: `test_normalize_row_prefers_text_over_numeric_severity`, `test_sweet32_severity_preserved_end_to_end`.

---

## 14. Encoding Strategy

Nessus exports can come in various encodings depending on OS and locale:

1. Try `chardet` auto-detection (if installed).
2. Try strict decoding in order: `utf-8-sig`, `utf-8`, `cp1252`, `latin1`, `iso-8859-1`.
3. Last resort: `utf-8` with `errors="replace"` (lossy but never fails).

The `utf-8-sig` is tried first because many Windows-generated CSVs include a BOM.

---

## 15. Testing

```bash
# Run all tests
.venv/bin/python -m pytest test_core.py -v

# Run a specific test class
.venv/bin/python -m pytest test_core.py::TestOmissionRules -v

# Run Django system check
.venv/bin/python main.py check
```

Test coverage areas:
- Omission rules (10 tests): blocklist, conditional, subnet boundaries
- Severity derivation (9 tests): text, numeric, CVSS fallback, collisions
- Column normalization (4 tests): known columns, case sensitivity, passthrough
- Deduplication (2 tests): exact dupes, different ports
- Sorting (1 test): severity ordering
- Excel safety (6 tests): formula injection, sheet name sanitization
- End-to-end (5 tests): full pipeline, minimal columns, omission, empty file, BytesIO
