"""
ELDEN RING - Target App (Intentionally Vulnerable Flask Application)

WARNING: This application contains INTENTIONAL vulnerabilities for security
testing and demonstration purposes. DO NOT deploy in production environments.

Vulnerable Endpoints:
  - POST /api/login  : SQL Injection (CWE-89)
  - GET  /api/search : Reflected XSS (CWE-79)
  - GET  /api/file   : Path Traversal (CWE-22)
"""

from flask import Flask, request, render_template_string, send_file, jsonify
import sqlite3
import os

app = Flask(__name__)
DB_PATH = os.environ.get("DB_PATH", "/app/data/users.db")


# ────────────────────────────────────────────────────
# Vulnerability 1: SQL Injection (CWE-89)
# User input is directly interpolated into SQL query
# ────────────────────────────────────────────────────
@app.route("/api/login", methods=["POST"])
def login_handler():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # VULNERABLE: string formatting instead of parameterized query
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    try:
        cursor.execute(query)
        user = cursor.fetchone()
    except sqlite3.OperationalError as e:
        conn.close()
        return jsonify({"status": "error", "message": str(e)}), 400
    conn.close()

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
    return jsonify({
        "app": "ELDEN RING Target App",
        "purpose": "Intentionally vulnerable application for security testing",
        "endpoints": [
            {"path": "/api/login", "method": "POST", "vulnerability": "SQL Injection (CWE-89)"},
            {"path": "/api/search", "method": "GET", "vulnerability": "Reflected XSS (CWE-79)"},
            {"path": "/api/file", "method": "GET", "vulnerability": "Path Traversal (CWE-22)"},
        ],
    }), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
