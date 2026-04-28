"""Static validation of the ModSecurity WAF ConfigMap.

Catches accidental regression of critical security settings on the
ingress-nginx ConfigMap (e.g., someone flipping SecRuleEngine to
DetectionOnly or disabling OWASP CRS).

Runs as a unit test — no cluster access required.
"""

from pathlib import Path

import pytest
import yaml


REPO_ROOT = Path(__file__).resolve().parents[3]
CONFIGMAP_PATH = REPO_ROOT / "kubernetes" / "service-mesh" / "ingress" / "configmap.yaml"


@pytest.fixture(scope="module")
def configmap_data() -> dict:
    assert CONFIGMAP_PATH.exists(), f"ConfigMap not found at {CONFIGMAP_PATH}"
    doc = yaml.safe_load(CONFIGMAP_PATH.read_text())
    assert doc.get("kind") == "ConfigMap"
    assert doc["metadata"]["namespace"] == "ingress-nginx"
    return doc["data"]


@pytest.fixture(scope="module")
def snippet(configmap_data: dict) -> str:
    return configmap_data.get("modsecurity-snippet", "")


class TestModSecurityToggle:
    def test_modsecurity_enabled(self, configmap_data):
        assert configmap_data.get("enable-modsecurity") == "true"

    def test_owasp_crs_enabled(self, configmap_data):
        assert configmap_data.get("enable-owasp-modsecurity-crs") == "true"

    def test_snippet_annotations_allowed(self, configmap_data):
        assert configmap_data.get("allow-snippet-annotations") == "true"


class TestRuleEngine:
    def test_block_mode_active(self, snippet):
        """SecRuleEngine must be On (full blocking), not DetectionOnly."""
        assert "SecRuleEngine On" in snippet, (
            "Block mode disabled — attacks would be logged but not blocked"
        )
        assert "SecRuleEngine DetectionOnly" not in snippet
        assert "SecRuleEngine Off" not in snippet


class TestRequestInspection:
    def test_request_body_inspection_enabled(self, snippet):
        assert "SecRequestBodyAccess On" in snippet

    def test_json_content_type_parsed(self, snippet):
        """JSON requests must be parsed so SQLi/XSS in JSON body is inspected."""
        assert "requestBodyProcessor=JSON" in snippet
        assert "application/json" in snippet

    def test_body_size_limit_enforced(self, snippet):
        """Oversize bodies must be rejected, not silently truncated."""
        assert "SecRequestBodyLimit" in snippet
        assert "SecRequestBodyLimitAction Reject" in snippet


class TestAuditPipeline:
    def test_audit_log_to_stdout(self, snippet):
        """Audit logs must go to stdout for the runtime-defense controller to ingest."""
        assert "SecAuditLog /dev/stdout" in snippet

    def test_audit_log_format_json(self, snippet):
        """Audit log format must be JSON for the ModSecurity adapter to parse."""
        assert "SecAuditLogFormat JSON" in snippet

    def test_audit_engine_active(self, snippet):
        """Audit engine must run on every relevant request to feed Phase 1 pipeline."""
        assert "SecAuditEngine RelevantOnly" in snippet
