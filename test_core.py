"""
Unit tests for the Nessus Report Generator core logic.

Run with:  pytest test_core.py -v

Tests cover:
  - Omission rules (ALWAYS_OMIT, SELF_SIGNED_PLUGINS, subnet exception)
  - Severity derivation
  - Column normalization
  - Deduplication
  - Formula injection prevention
  - Sheet name sanitization
  - End-to-end CSV→Excel pipeline (happy path)
  - Edge cases (missing columns, empty files)
"""

import os
import sys
import tempfile

import pytest

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.csv_processor import (
    Finding,
    apply_omission_rules,
    cvss_to_severity,
    derive_severity,
    ip_in_subnet,
    normalize_column_name,
    normalize_row,
    process_csv_files,
    read_csv_rows,
    remove_duplicates,
    should_omit_row,
    sort_by_severity,
)
from core.excel_writer import safe_cell_value, sanitize_sheet_name, write_excel_report


# =============================================================================
# Omission rules
# =============================================================================

class TestOmissionRules:
    """Tests for the two-tier plugin omission logic."""

    def test_always_omit_removes_matching_plugin(self) -> None:
        """Plugins in ALWAYS_OMIT are removed regardless of host."""
        row: Finding = {
            "plugin_name": "SSL Certificate Expiry",
            "ip_address": "10.0.0.1",
        }
        assert should_omit_row(row) is True

    def test_always_omit_case_insensitive(self) -> None:
        """ALWAYS_OMIT matching is case-insensitive."""
        row: Finding = {
            "plugin_name": "  SSL CERTIFICATE EXPIRY  ",
            "ip_address": "10.0.0.1",
        }
        assert should_omit_row(row) is True

    def test_self_signed_omitted_for_non_exempt_ip(self) -> None:
        """Self-signed plugin is omitted for IPs outside the exempt subnet."""
        row: Finding = {
            "plugin_name": "SSL Self-Signed Certificate",
            "ip_address": "10.0.0.1",
        }
        assert should_omit_row(row) is True

    def test_self_signed_kept_for_exempt_subnet(self) -> None:
        """Self-signed plugin is KEPT for IPs in 192.168.195.0/24."""
        row: Finding = {
            "plugin_name": "SSL Self-Signed Certificate",
            "ip_address": "192.168.195.42",
        }
        assert should_omit_row(row) is False

    def test_self_signed_omitted_for_hostname(self) -> None:
        """Self-signed plugin is omitted when Host is a hostname (not IP)."""
        row: Finding = {
            "plugin_name": "SSL/TLS Self-Signed Certificate",
            "ip_address": "server.example.com",
        }
        assert should_omit_row(row) is True

    def test_self_signed_omitted_for_empty_host(self) -> None:
        """Self-signed plugin is omitted when Host is empty."""
        row: Finding = {
            "plugin_name": "SSL Certificate Cannot Be Trusted",
            "ip_address": "",
        }
        assert should_omit_row(row) is True

    def test_non_omit_plugin_kept(self) -> None:
        """Plugins NOT in any omission list are kept."""
        row: Finding = {
            "plugin_name": "Apache Tomcat Version Detection",
            "ip_address": "10.0.0.1",
        }
        assert should_omit_row(row) is False

    def test_apply_omission_rules_batch(self) -> None:
        """apply_omission_rules filters a batch correctly."""
        rows: list[Finding] = [
            {"plugin_name": "SSL Certificate Expiry", "ip_address": "10.0.0.1"},
            {"plugin_name": "Apache Detection", "ip_address": "10.0.0.2"},
            {"plugin_name": "SSL Self-Signed Certificate", "ip_address": "192.168.195.10"},
            {"plugin_name": "SSL Self-Signed Certificate", "ip_address": "10.0.0.3"},
        ]
        result = apply_omission_rules(rows)
        assert len(result) == 2
        names = [r["plugin_name"] for r in result]
        assert "Apache Detection" in names
        assert "SSL Self-Signed Certificate" in names  # kept for 192.168.195.10

    def test_subnet_boundary_255(self) -> None:
        """192.168.195.255 is in the /24 subnet."""
        assert ip_in_subnet("192.168.195.255") is True

    def test_subnet_boundary_outside(self) -> None:
        """192.168.196.0 is NOT in 192.168.195.0/24."""
        assert ip_in_subnet("192.168.196.0") is False


# =============================================================================
# Severity derivation
# =============================================================================

class TestSeverityDerivation:
    """Tests for severity derivation from text / CVSS scores."""

    def test_text_severity_critical(self) -> None:
        assert derive_severity({"severity": "Critical"}) == "Critical"

    def test_text_severity_numeric(self) -> None:
        assert derive_severity({"severity": "4"}) == "Critical"

    def test_cvss_v3_fallback(self) -> None:
        row: Finding = {"severity": "", "cvss_v3_base_score": "9.8"}
        assert derive_severity(row) == "Critical"

    def test_cvss_v2_fallback(self) -> None:
        row: Finding = {"severity": "", "cvss_v3_base_score": "", "cvss_v2_base_score": "5.0"}
        assert derive_severity(row) == "Medium"

    def test_default_informational(self) -> None:
        assert derive_severity({}) == "Informational"

    def test_cvss_to_severity_edge_cases(self) -> None:
        assert cvss_to_severity("0.0") == "Informational"
        assert cvss_to_severity("10.0") == "Critical"
        assert cvss_to_severity("invalid") == "Informational"
        assert cvss_to_severity("11.0") == "Critical"

    # ── Regression: SWEET32 column collision ─────────────────────────

    def test_normalize_row_prefers_text_over_numeric_severity(self) -> None:
        """When CSV has both 'Risk: High' and 'Severity: 2', text wins."""
        # Simulate Nessus CSV with Risk column BEFORE Severity column
        raw = {"Risk": "High", "Severity": "2", "Host": "10.0.0.1"}
        norm = normalize_row(raw)
        assert norm["severity"] == "High"

    def test_normalize_row_prefers_text_reverse_order(self) -> None:
        """Column order in CSV shouldn't matter — text still wins."""
        # Simulate Nessus CSV with Severity column BEFORE Risk column
        from collections import OrderedDict
        raw = OrderedDict([("Severity", "2"), ("Risk", "High"), ("Host", "10.0.0.1")])
        norm = normalize_row(raw)
        assert norm["severity"] == "High"

    def test_sweet32_severity_preserved_end_to_end(self) -> None:
        """SWEET32 with Risk=High and CVSS v2=5.0 must remain High."""
        row: Finding = {
            "severity": "High",
            "cvss_v2_base_score": "5.0",
            "cvss_v3_base_score": "",
        }
        assert derive_severity(row) == "High"

    def test_normalize_row_plugin_name_last_wins(self) -> None:
        """When 'Plugin' (ID) and 'Name' (text) both map to plugin_name,
        the last column value wins — preserving the actual name."""
        from collections import OrderedDict
        raw = OrderedDict([
            ("Plugin", "42873"),
            ("Name", "SSL Medium Strength Cipher Suites Supported (SWEET32)"),
            ("Host", "10.0.0.1"),
        ])
        norm = normalize_row(raw)
        assert norm["plugin_name"] == "SSL Medium Strength Cipher Suites Supported (SWEET32)"


# =============================================================================
# Column normalization
# =============================================================================

class TestColumnNormalization:
    """Tests for CSV column name normalization."""

    def test_known_column(self) -> None:
        assert normalize_column_name("Plugin Name") == "plugin_name"

    def test_case_insensitive(self) -> None:
        assert normalize_column_name("  HOST  ") == "ip_address"

    def test_unknown_column_passthrough(self) -> None:
        assert normalize_column_name("Custom Column") == "Custom Column"

    def test_normalize_row(self) -> None:
        raw = {"Plugin Name": "Vuln A", "Host": "10.0.0.1", "Custom": "val"}
        norm = normalize_row(raw)
        assert "plugin_name" in norm
        assert "ip_address" in norm
        assert "Custom" in norm


# =============================================================================
# Deduplication
# =============================================================================

class TestDeduplication:
    """Tests for finding deduplication."""

    def test_removes_exact_dupes(self) -> None:
        rows = [
            {"ip_address": "10.0.0.1", "plugin_name": "Vuln A", "port": "80"},
            {"ip_address": "10.0.0.1", "plugin_name": "Vuln A", "port": "80"},
            {"ip_address": "10.0.0.1", "plugin_name": "Vuln B", "port": "80"},
        ]
        result = remove_duplicates(rows)
        assert len(result) == 2

    def test_keeps_different_ports(self) -> None:
        rows = [
            {"ip_address": "10.0.0.1", "plugin_name": "Vuln A", "port": "80"},
            {"ip_address": "10.0.0.1", "plugin_name": "Vuln A", "port": "443"},
        ]
        result = remove_duplicates(rows)
        assert len(result) == 2


# =============================================================================
# Sorting
# =============================================================================

class TestSorting:
    """Tests for severity-based sorting."""

    def test_sort_order(self) -> None:
        rows = [
            {"severity": "Low", "ip_address": "10.0.0.1"},
            {"severity": "Critical", "ip_address": "10.0.0.2"},
            {"severity": "High", "ip_address": "10.0.0.3"},
        ]
        sorted_rows = sort_by_severity(rows)
        severities = [r["severity"] for r in sorted_rows]
        assert severities == ["Critical", "High", "Low"]


# =============================================================================
# Excel safety helpers
# =============================================================================

class TestExcelSafety:
    """Tests for formula injection prevention and sheet name sanitization."""

    def test_formula_injection_equals(self) -> None:
        assert safe_cell_value("=1+1") == "'=1+1"

    def test_formula_injection_plus(self) -> None:
        assert safe_cell_value("+cmd|'/C calc'!A0") == "'+cmd|'/C calc'!A0"

    def test_formula_injection_minus(self) -> None:
        assert safe_cell_value("-1+1") == "'-1+1"

    def test_formula_injection_at(self) -> None:
        assert safe_cell_value("@SUM(A1)") == "'@SUM(A1)"

    def test_normal_value_unchanged(self) -> None:
        assert safe_cell_value("Hello World") == "Hello World"

    def test_empty_value(self) -> None:
        assert safe_cell_value("") == ""
        assert safe_cell_value(None) == ""

    def test_sheet_name_sanitization(self) -> None:
        assert sanitize_sheet_name("Test [Sheet]") == "Test _Sheet_"

    def test_sheet_name_max_length(self) -> None:
        long_name = "A" * 50
        assert len(sanitize_sheet_name(long_name)) == 31


# =============================================================================
# End-to-end pipeline (integration)
# =============================================================================

class TestEndToEnd:
    """Integration tests using real temp files."""

    @staticmethod
    def _make_csv(content: str) -> str:
        """Write CSV content to a temp file and return the path."""
        fd, path = tempfile.mkstemp(suffix=".csv")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
        return path

    def test_happy_path(self) -> None:
        """Full pipeline: CSV → list of Findings → Excel."""
        csv_content = (
            "Plugin ID,CVE,CVSS v3.0 Base Score,Risk,Host,Protocol,Port,"
            "Name,Synopsis,Description,Solution,Plugin Output\n"
            '1001,CVE-2023-1234,9.8,Critical,192.168.1.10,tcp,443,'
            'Critical Vuln,Bad stuff,Very bad,Patch it,"Output 1"\n'
            '1002,CVE-2023-5678,7.5,High,192.168.1.11,tcp,80,'
            'High Vuln,Bad stuff,Bad stuff,Patch it,"Output 2"\n'
        )
        csv_path = self._make_csv(csv_content)
        try:
            rows = process_csv_files([csv_path])
            assert len(rows) == 2
            assert rows[0]["Severity"] == "Critical"
            assert rows[1]["Severity"] == "High"

            # Write Excel
            xlsx_fd, xlsx_path = tempfile.mkstemp(suffix=".xlsx")
            os.close(xlsx_fd)
            result = write_excel_report(rows, xlsx_path)
            assert os.path.exists(result)
            assert os.path.getsize(result) > 0
        finally:
            os.unlink(csv_path)
            if os.path.exists(xlsx_path):
                os.unlink(xlsx_path)

    def test_missing_columns_still_works(self) -> None:
        """CSV with minimal columns still produces output."""
        csv_content = "Host,Name\n10.0.0.1,Some Vuln\n"
        csv_path = self._make_csv(csv_content)
        try:
            rows = process_csv_files([csv_path])
            assert len(rows) == 1
            assert rows[0].get("IP Address") == "10.0.0.1"
        finally:
            os.unlink(csv_path)

    def test_omission_in_pipeline(self) -> None:
        """Omission rules are applied during the pipeline."""
        csv_content = (
            "Host,Name,Port\n"
            "10.0.0.1,SSL Certificate Expiry,443\n"
            "10.0.0.1,Apache Detection,80\n"
            "192.168.195.5,SSL Self-Signed Certificate,443\n"
        )
        csv_path = self._make_csv(csv_content)
        try:
            rows = process_csv_files([csv_path])
            names = [r.get("Issue Name", "") for r in rows]
            # SSL Certificate Expiry should be omitted (ALWAYS_OMIT)
            assert "SSL Certificate Expiry" not in names
            # Apache Detection should be kept
            assert "Apache Detection" in names
            # SSL Self-Signed Certificate should be kept (exempt subnet)
            assert "SSL Self-Signed Certificate" in names
        finally:
            os.unlink(csv_path)

    def test_empty_csv_raises(self) -> None:
        """Empty CSV raises CSVProcessingError."""
        from core.csv_processor import CSVProcessingError

        csv_path = self._make_csv("")
        try:
            with pytest.raises(CSVProcessingError):
                process_csv_files([csv_path])
        finally:
            os.unlink(csv_path)

    def test_excel_output_to_bytesio(self) -> None:
        """write_excel_report accepts BytesIO for testability."""
        from io import BytesIO

        rows: list[Finding] = [
            {"IP Address": "10.0.0.1", "Issue Name": "Test Vuln",
             "Severity": "High", "Port": "80", "Protocol": "tcp",
             "CVE": "", "Description": "", "Impact": "",
             "Steps to Remediate": "", "Plugin Output": "",
             "See Also": "", "Vulnerability Priority Rating": "",
             "Exploit Prediction System (EPSS)": ""},
        ]
        buf = BytesIO()
        write_excel_report(rows, buf)
        assert buf.tell() > 0 or len(buf.getvalue()) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
