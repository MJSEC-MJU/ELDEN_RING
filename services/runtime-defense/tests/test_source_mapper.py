"""Tests for source code mapper."""

import json
import os
import tempfile

from src.source_mapper import SourceMapper

SAMPLE_ROUTES = {
    "POST /api/login": {
        "file": "app.py",
        "function": "login_handler",
        "line_start": 14,
        "line_end": 27,
        "vulnerability": "SQL Injection",
        "cwe_id": "CWE-89",
    },
    "GET /api/search": {
        "file": "app.py",
        "function": "search_handler",
        "line_start": 33,
        "line_end": 38,
        "vulnerability": "Reflected XSS",
        "cwe_id": "CWE-79",
    },
    "GET /api/file": {
        "file": "app.py",
        "function": "file_handler",
        "line_start": 44,
        "line_end": 50,
        "vulnerability": "Path Traversal",
        "cwe_id": "CWE-22",
    },
}


class TestSourceMapper:
    def setup_method(self):
        self.tmpfile = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        )
        json.dump(SAMPLE_ROUTES, self.tmpfile)
        self.tmpfile.close()
        self.mapper = SourceMapper(self.tmpfile.name)

    def teardown_method(self):
        os.unlink(self.tmpfile.name)

    def test_map_existing_endpoint(self):
        result = self.mapper.map("POST", "/api/login")
        assert result is not None
        assert result["file"] == "app.py"
        assert result["function"] == "login_handler"
        assert result["line_start"] == 14
        assert result["line_end"] == 27

    def test_map_search_endpoint(self):
        result = self.mapper.map("GET", "/api/search")
        assert result is not None
        assert result["function"] == "search_handler"

    def test_map_nonexistent_endpoint(self):
        result = self.mapper.map("DELETE", "/api/unknown")
        assert result is None

    def test_missing_route_map_file(self):
        mapper = SourceMapper("/nonexistent/path.json")
        assert mapper.map("GET", "/api/anything") is None
