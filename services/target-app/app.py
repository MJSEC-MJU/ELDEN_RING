"""
ELDEN RING - Target App (Intentionally Vulnerable Flask Application)

WARNING: This application contains INTENTIONAL vulnerabilities for security
testing and demonstration purposes. DO NOT deploy in production environments.

Vulnerable Endpoints:
  - POST /api/login  : SQL Injection (CWE-89)
  - GET  /api/search : Reflected XSS (CWE-79)
  - GET  /api/file   : Path Traversal (CWE-22)
"""

import os
import json
import sqlite3
import urllib.error
import urllib.request

from flask import Flask, request, render_template, render_template_string, send_file, jsonify

app = Flask(__name__)
DB_PATH = os.environ.get("DB_PATH", "/app/data/users.db")
RUNTIME_DEFENSE_URL = os.environ.get("RUNTIME_DEFENSE_URL", "http://runtime-defense:8080")
SQLI_MARKERS = (" or ", " and ", "--", "/*", "*/", "'", "\"", " union ", " sleep(", "1=1")
XSS_MARKERS = ("<script", "</script", "javascript:", "onerror=", "onload=", "<img", "alert(")
PATH_TRAVERSAL_MARKERS = ("../", "..\\", "%2e%2e", "/etc/passwd", "/etc/hostname", "windows/win.ini")


def looks_like_sqli(*values: str) -> bool:
    combined = " ".join(values).lower()
    return any(marker in combined for marker in SQLI_MARKERS)


def looks_like_xss(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in XSS_MARKERS)


def looks_like_path_traversal(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in PATH_TRAVERSAL_MARKERS)


def report_attack(
    attack_category: str,
    endpoint: dict[str, str],
    payload_sample: str,
    severity: str = "HIGH",
    *,
    blocked: bool = False,
    requires_patch: bool = True,
    defense_action_taken: str = "rate_limit",
) -> None:
    if not RUNTIME_DEFENSE_URL:
        return
    if request.headers.get("X-ELDEN-Probe"):
        return

    payload = {
        "attack_category": attack_category,
        "target_endpoint": endpoint,
        "payload_sample": payload_sample,
        "source_ip": request.headers.get("X-Forwarded-For", request.remote_addr or "unknown"),
        "severity": severity,
        "blocked": blocked,
        "requires_patch": requires_patch,
        "defense_action_taken": defense_action_taken,
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"{RUNTIME_DEFENSE_URL.rstrip('/')}/api/v1/events/manual",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=1.5).read()
    except (urllib.error.URLError, TimeoutError, OSError):
        # The vulnerable app should keep responding even if the defense plane is unavailable.
        pass


def report_sqli_attempt(
    username: str,
    password: str,
    *,
    blocked: bool = False,
    requires_patch: bool = True,
    defense_action_taken: str = "rate_limit",
) -> None:
    report_attack(
        "SQL Injection",
        {"method": "POST", "path": "/api/login"},
        f"username={username}&password={password}",
        blocked=blocked,
        requires_patch=requires_patch,
        defense_action_taken=defense_action_taken,
    )


# ────────────────────────────────────────────────────
# Vulnerability 1: SQL Injection (CWE-89)
# User input is directly interpolated into SQL query
# ────────────────────────────────────────────────────
@app.route("/api/login", methods=["POST"])
def login_handler():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    suspicious = looks_like_sqli(username, password)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # VULNERABLE: string formatting instead of parameterized query
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    try:
        cursor.execute(query)
        user = cursor.fetchone()
    except sqlite3.OperationalError as e:
        conn.close()
        if suspicious:
            report_sqli_attempt(username, password, defense_action_taken="sql_error")
        return jsonify({"status": "error", "message": str(e)}), 400
    conn.close()

    if suspicious:
        exploit_succeeded = user is not None
        report_sqli_attempt(
            username,
            password,
            blocked=not exploit_succeeded,
            requires_patch=exploit_succeeded,
            defense_action_taken="exploit_succeeded" if exploit_succeeded else "application_rejected",
        )

    if user:
        return jsonify({"status": "success", "user": user[1]}), 200
    return jsonify({"status": "fail", "message": "Invalid credentials"}), 401


# ────────────────────────────────────────────────────
# Vulnerability 2: Reflected XSS (CWE-79)
# User input rendered directly into HTML without escaping
# ────────────────────────────────────────────────────
@app.route("/api/search", methods=["GET"])
def search_handler():
    query = request.args.get("q", "")
    if looks_like_xss(query):
        report_attack(
            "Cross-Site Scripting",
            {"method": "GET", "path": "/api/search"},
            f"q={query}",
            severity="MEDIUM",
        )
    # VULNERABLE: user input injected directly into HTML
    html = (
        f"<html><body>"
        f"<h1>Search Results for: {query}</h1>"
        f"<p>No results found.</p>"
        f"</body></html>"
    )
    return render_template_string(html)


# ────────────────────────────────────────────────────
# Vulnerability 3: Path Traversal (CWE-22)
# File path not sanitized, allows directory traversal
# ────────────────────────────────────────────────────
@app.route("/api/file", methods=["GET"])
def file_handler():
    filename = request.args.get("name", "")
    if looks_like_path_traversal(filename):
        report_attack(
            "Path Traversal",
            {"method": "GET", "path": "/api/file"},
            f"name={filename}",
            severity="HIGH",
        )
    # VULNERABLE: no path traversal filtering
    filepath = os.path.join("/app/uploads", filename)
    if os.path.exists(filepath):
        return send_file(filepath)
    return jsonify({"error": "File not found"}), 404


# ────────────────────────────────────────────────────
# Health check endpoints
# ────────────────────────────────────────────────────
@app.route("/healthz")
def health():
    return jsonify({"status": "ok"}), 200


@app.route("/readyz")
def ready():
    if os.path.exists(DB_PATH):
        return jsonify({"status": "ready"}), 200
    return jsonify({"status": "not ready", "reason": "database not initialized"}), 503


@app.route("/")
def index():
    return render_template("index.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
