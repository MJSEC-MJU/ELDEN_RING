from __future__ import annotations

import argparse
import ast
from pathlib import Path


def replace_function(source: str, function_name: str, replacement: str) -> str:
    tree = ast.parse(source)
    lines = source.splitlines()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == function_name and node.end_lineno:
            return "\n".join(
                lines[: node.lineno - 1] + replacement.rstrip().splitlines() + lines[node.end_lineno :]
            ) + "\n"
    raise SystemExit(f"function not found: {function_name}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Apply deployed fixes to the live target-app workspace.")
    parser.add_argument("--root", default=".", help="Repository root")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    app_path = root / "runtime" / "live-workspace" / "services" / "target-app" / "app.py"
    text = app_path.read_text(encoding="utf-8")
    if "import html" not in text:
        text = text.replace("import json\n", "import json\nimport html\n", 1)

    updated = replace_function(
        text,
        "login_handler",
        '''
def login_handler():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    suspicious = looks_like_sqli(username, password)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username=? AND password=?"
    try:
        cursor.execute(query, (username, password))
        user = cursor.fetchone()
    except sqlite3.OperationalError:
        conn.close()
        if suspicious:
            report_sqli_attempt(username, password, defense_action_taken="sql_error")
        return jsonify({"status": "error", "message": "Database error"}), 400
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
''',
    )
    updated = replace_function(
        updated,
        "search_handler",
        '''
def search_handler():
    query = request.args.get("q", "")
    if looks_like_xss(query):
        report_attack(
            "Cross-Site Scripting",
            {"method": "GET", "path": "/api/search"},
            f"q={query}",
            severity="MEDIUM",
            blocked=True,
            requires_patch=False,
            defense_action_taken="application_rejected",
        )
    escaped_query = html.escape(query)
    safe_html = (
        f"<html><body>"
        f"<h1>Search Results for: {escaped_query}</h1>"
        f"<p>No results found.</p>"
        f"</body></html>"
    )
    return render_template_string(safe_html)
''',
    )
    updated = replace_function(
        updated,
        "file_handler",
        '''
def file_handler():
    filename = request.args.get("name", "")
    base_dir = os.path.realpath("/app/uploads")
    filepath = os.path.realpath(os.path.join(base_dir, filename))
    inside_base = filepath == base_dir or filepath.startswith(base_dir + os.sep)
    if looks_like_path_traversal(filename) or not inside_base:
        report_attack(
            "Path Traversal",
            {"method": "GET", "path": "/api/file"},
            f"name={filename}",
            severity="HIGH",
            blocked=True,
            requires_patch=False,
            defense_action_taken="application_rejected",
        )
        return jsonify({"error": "File not found"}), 404
    if os.path.exists(filepath) and os.path.isfile(filepath):
        return send_file(filepath)
    return jsonify({"error": "File not found"}), 404
''',
    )
    if "cursor.execute(query, (username, password))" not in updated:
        raise SystemExit("failed to apply parameterized SQL query")
    if "requires_patch=exploit_succeeded" not in updated:
        raise SystemExit("target-app reporting metadata changes are missing")
    if "escaped_query = html.escape(query)" not in updated:
        raise SystemExit("failed to apply XSS escaping")
    if "inside_base =" not in updated or "requires_patch=False" not in updated:
        raise SystemExit("failed to apply path traversal blocking")

    app_path.write_text(updated, encoding="utf-8")
    print(f"patched live target-app fixes/reporting: {app_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
