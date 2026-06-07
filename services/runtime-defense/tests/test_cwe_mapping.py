"""Tests for CWE rule table mapping."""

from src.cwe_mapping import map_to_cwe


class TestCWEMapping:
    def test_sql_injection(self):
        result = map_to_cwe("SQL Injection")
        assert result["cwe_id"] == "CWE-89"
        assert result["owasp"] == "A03:2021"

    def test_xss(self):
        result = map_to_cwe("Cross-Site Scripting")
        assert result["cwe_id"] == "CWE-79"

    def test_path_traversal(self):
        result = map_to_cwe("Path Traversal")
        assert result["cwe_id"] == "CWE-22"
        assert result["owasp"] == "A01:2021"

    def test_shell_execution(self):
        result = map_to_cwe("Shell Execution")
        assert result["cwe_id"] == "CWE-78"

    def test_privilege_escalation(self):
        result = map_to_cwe("Privilege Escalation")
        assert result["cwe_id"] == "CWE-269"

    def test_unknown_category(self):
        result = map_to_cwe("Something Unknown")
        assert result["cwe_id"] == "UNKNOWN"

    def test_case_insensitive(self):
        result = map_to_cwe("sql injection")
        assert result["cwe_id"] == "CWE-89"

    def test_whitespace_handling(self):
        result = map_to_cwe("  SQL Injection  ")
        assert result["cwe_id"] == "CWE-89"
