"""CWE Rule Table - deterministic mapping from attack category to CWE."""

CWE_MAP = {
    # Web attacks (ModSecurity)
    "SQL Injection": {
        "cwe_id": "CWE-89",
        "cwe_name": "Improper Neutralization of Special Elements used in an SQL Command",
        "owasp": "A03:2021",
    },
    "Cross-Site Scripting": {
        "cwe_id": "CWE-79",
        "cwe_name": "Improper Neutralization of Input During Web Page Generation",
        "owasp": "A03:2021",
    },
    "Path Traversal": {
        "cwe_id": "CWE-22",
        "cwe_name": "Improper Limitation of a Pathname to a Restricted Directory",
        "owasp": "A01:2021",
    },
    # System attacks (Falco)
    "Shell Execution": {
        "cwe_id": "CWE-78",
        "cwe_name": "Improper Neutralization of Special Elements used in an OS Command",
        "owasp": "A03:2021",
    },
    "Privilege Escalation": {
        "cwe_id": "CWE-269",
        "cwe_name": "Improper Privilege Management",
        "owasp": "A04:2021",
    },
    "File Tampering": {
        "cwe_id": "CWE-284",
        "cwe_name": "Improper Access Control",
        "owasp": "A01:2021",
    },
    "Suspicious Network": {
        "cwe_id": "CWE-918",
        "cwe_name": "Server-Side Request Forgery",
        "owasp": "A10:2021",
    },
    # Phase 1 Week 11 — detection scope expansion (6-category coverage)
    "Command Injection": {
        "cwe_id": "CWE-78",
        "cwe_name": "Improper Neutralization of Special Elements used in an OS Command",
        "owasp": "A03:2021",
    },
    "Server-Side Request Forgery": {
        "cwe_id": "CWE-918",
        "cwe_name": "Server-Side Request Forgery",
        "owasp": "A10:2021",
    },
    "Insecure Deserialization": {
        "cwe_id": "CWE-502",
        "cwe_name": "Deserialization of Untrusted Data",
        "owasp": "A08:2021",
    },
}

UNKNOWN_CWE = {"cwe_id": "UNKNOWN", "cwe_name": "Unmapped Attack Type", "owasp": "UNKNOWN"}


def map_to_cwe(attack_category: str) -> dict:
    """Map attack_category to CWE. Returns UNKNOWN on miss."""
    for key, value in CWE_MAP.items():
        if key.lower() == attack_category.strip().lower():
            return value
    return UNKNOWN_CWE.copy()
