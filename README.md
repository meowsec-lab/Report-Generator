# Nessus Report Generator (VAPT Platform)

A Django web application that converts Nessus vulnerability scan CSV exports into professionally formatted Excel reports. Supports both fresh reports and rescan comparisons to track remediation progress.

## Quick Start

```bash
# 1. Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the application
python main.py
```

Open **http://127.0.0.1:8000/** in your browser.

## Features

- **New Report**: Upload one or more Nessus CSVs → get a formatted Excel report with severity analysis, deduplication, and IP summary.
- **Rescan Comparison**: Compare new scans against a previous report to identify New, Open, and Resolved findings.
- **Automatic column mapping**: Handles various Nessus CSV column name variations.
- **Two-tier plugin omission**: Filters noise (SSL cert plugins) with subnet-based exceptions.
- **Formula injection prevention**: Sanitizes cell values to prevent Excel exploits.

## Documentation

See **[reports/CONTEXT.md](reports/CONTEXT.md)** for comprehensive documentation of all business logic, data flows, and step-by-step recipes for making changes to the reports app.

## License

MIT License
