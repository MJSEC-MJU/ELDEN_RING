from __future__ import annotations

from typing import Any

from .config import PlaneSettings
from .schemas import AnalysisFinding, AnalysisScope, AnalyzeResponse, VulnerabilityContext
from .storage import PlaneStore
from .utils import dump_model, extract_code_window, file_exists, resolve_workspace_path, write_json


class SecureCodingAnalysisEngine:
    def __init__(self, settings: PlaneSettings, store: PlaneStore, artifact_root) -> None:
        self.settings = settings
        self.store = store
        self.artifact_root = artifact_root

    def run_analysis(self, job_id: str, context: dict[str, Any]) -> AnalyzeResponse:
        self.store.update_secure_job(job_id, status="ANALYZING", current_step="analyze", progress=20)
        code_context = self.load_code_context(context)
        scope = AnalysisScope(
            primary_file=context["target"]["source_mapping"]["file"],
            primary_function=context["target"]["source_mapping"]["function"],
            line_start=context["target"]["source_mapping"]["line_start"],
            line_end=context["target"]["source_mapping"]["line_end"],
            related_files=[],
            code_window=code_context["snippet"],
        )
        finding = self._make_finding(context)
        vulnerability_context = VulnerabilityContext(source="runtime-defense-context", findings=[finding])
        payload = AnalyzeResponse(job_id=job_id, status="success", analysis_scope=scope, vulnerability_context=vulnerability_context)
        write_json(self.artifact_root / "analysis" / f"{job_id}.json", dump_model(payload))
        self.store.save_secure_analysis(job_id, dump_model(scope), dump_model(vulnerability_context))
        return payload

    def load_code_context(self, context: dict[str, Any]) -> dict[str, Any]:
        relative_file = context["target"]["source_mapping"]["file"]
        line_start = context["target"]["source_mapping"]["line_start"]
        line_end = context["target"]["source_mapping"]["line_end"]
        resolved = resolve_workspace_path(self.settings.workspace_root, relative_file)
        if file_exists(resolved):
            full_content = resolved.read_text(encoding="utf-8")
            snippet, _, _ = extract_code_window(full_content, line_start, line_end)
            return {"resolved_path": resolved, "full_content": full_content, "snippet": snippet}
        snippet = self._default_vulnerable_snippet(context["attack_info"]["cwe_id"])
        return {"resolved_path": None, "full_content": snippet, "snippet": snippet}

    def _make_finding(self, context: dict[str, Any]) -> AnalysisFinding:
        cwe_id = context["attack_info"]["cwe_id"]
        if cwe_id == "CWE-89":
            rule_id, message = "custom.python.raw-sql", "User input flows into raw SQL query"
        elif cwe_id == "CWE-79":
            rule_id, message = "custom.python.xss-output", "User-controlled content is returned without output encoding"
        else:
            rule_id, message = "custom.python.path-traversal", "User-controlled path is used without canonicalization"
        return AnalysisFinding(
            rule_id=rule_id,
            file=context["target"]["source_mapping"]["file"],
            function=context["target"]["source_mapping"]["function"],
            line=context["target"]["source_mapping"]["line_start"],
            message=message,
            severity="ERROR",
        )

    def _default_vulnerable_snippet(self, cwe_id: str) -> str:
        if cwe_id == "CWE-89":
            return "\n".join(
                [
                    "def login_handler(username, password):",
                    "    query = f\"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'\"",
                    "    result = db.execute(query)",
                    "    return result",
                ]
            )
        if cwe_id == "CWE-79":
            return "\n".join(["def render_feedback(content):", "    return f\"<div>{content}</div>\""])
        return "\n".join(["def download_file(filename):", "    return open(os.path.join(BASE_DIR, filename), 'rb').read()"])
