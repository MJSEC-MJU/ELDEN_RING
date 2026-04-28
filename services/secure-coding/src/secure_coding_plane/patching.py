from __future__ import annotations

import difflib
from pathlib import Path
from typing import Any

from fastapi import HTTPException

from .config import PlaneSettings
from .llm_clients import LlmPatchClientError, create_patch_client
from .schemas import PatchPayload, PatchResponse, PatchStrategy, RecheckResponse, RecheckResult
from .storage import PlaneStore
from .utils import generate_id, write_text


class SecureCodingPatchEngine:
    def __init__(self, settings: PlaneSettings, store: PlaneStore, artifact_root) -> None:
        self.settings = settings
        self.store = store
        self.artifact_root = artifact_root
        self.patch_client = None if settings.secure_coding_llm_provider.lower() == "mock" else create_patch_client(settings)

    def run_patch(
        self,
        job_id: str,
        context: dict[str, Any],
        strategy: PatchStrategy,
        code_context: dict[str, Any],
    ) -> PatchResponse:
        self.store.update_secure_job(job_id, status="PATCH_GENERATING", current_step="patch", progress=60)
        llm_patch = self._generate_patch_payload(job_id, context, code_context, strategy)
        patched_snippet = llm_patch["patched_snippet"]
        patched_content = self._materialize_patched_content(context, code_context, patched_snippet)
        unified_diff = "".join(
            difflib.unified_diff(
                code_context["full_content"].splitlines(keepends=True),
                patched_content.splitlines(keepends=True),
                fromfile=f"a/{context['target']['source_mapping']['file']}",
                tofile=f"b/{context['target']['source_mapping']['file']}",
            )
        )
        if not unified_diff:
            unified_diff = "".join(
                difflib.unified_diff(
                    code_context["snippet"].splitlines(keepends=True),
                    patched_snippet.splitlines(keepends=True),
                    fromfile=f"a/{context['target']['source_mapping']['file']}",
                    tofile=f"b/{context['target']['source_mapping']['file']}",
                )
            )
        patch_id = generate_id("patch")
        patch_path = self.artifact_root / "patches" / f"{patch_id}.diff"
        write_text(patch_path, unified_diff)
        patched_file_path = None
        if code_context["resolved_path"] is not None:
            original_output = self.artifact_root / "original_src" / job_id / context["target"]["source_mapping"]["file"]
            write_text(original_output, code_context["full_content"])
            patched_output = self.artifact_root / "patched_src" / job_id / context["target"]["source_mapping"]["file"]
            write_text(patched_output, patched_content)
            patched_file_path = str(patched_output)
        change_summary = {
            "files_changed": 1,
            "functions_changed": [context["target"]["source_mapping"]["function"]],
            "security_fix": llm_patch["change_summary"].get("security_fix", strategy.fix_actions[0]),
            "llm_provider": llm_patch.get("provider", self.settings.secure_coding_llm_provider),
            "llm_model": llm_patch.get("model"),
        }
        patch = PatchPayload(
            patch_id=patch_id,
            target_file=context["target"]["source_mapping"]["file"],
            target_function=context["target"]["source_mapping"]["function"],
            patch_file=str(patch_path),
            unified_diff=unified_diff,
            patch_status="READY_FOR_RECHECK",
            change_summary=change_summary,
        )
        self.store.save_secure_patch(
            patch_id=patch_id,
            job_id=job_id,
            event_id=context["event_id"],
            target_file=patch.target_file,
            target_function=patch.target_function,
            patch_file=patch.patch_file,
            unified_diff=patch.unified_diff,
            patch_status=patch.patch_status,
            change_summary=patch.change_summary,
            patched_file_path=patched_file_path,
        )
        return PatchResponse(job_id=job_id, status="success", patch=patch)

    def run_recheck(self, job_id: str, patch_id: str) -> RecheckResponse:
        self.store.update_secure_job(job_id, status="SAFETY_RECHECKING", current_step="recheck", progress=80)
        patch_row = self.store.get_secure_patch(patch_id)
        if not patch_row:
            raise HTTPException(status_code=404, detail="Patch not found")
        patched_content = ""
        if patch_row.get("patched_file_path"):
            patched_content = Path(patch_row["patched_file_path"]).read_text(encoding="utf-8")
        syntax_valid = True
        if patch_row.get("patched_file_path", "").endswith(".py") and patched_content:
            try:
                compile(patched_content, patch_row["patched_file_path"], "exec")
            except SyntaxError:
                syntax_valid = False
        safety_checks_passed = self._patched_content_is_safe(patch_row["unified_diff"])
        recheck = RecheckResult(
            syntax_valid=syntax_valid,
            safety_checks_passed=safety_checks_passed,
            remaining_findings=[] if safety_checks_passed else [{"message": "Potential vulnerable pattern remains"}],
            patch_status="READY_FOR_BUILD" if syntax_valid and safety_checks_passed else "REJECTED",
        )
        self.store.save_secure_patch(
            patch_id=patch_row["patch_id"],
            job_id=patch_row["job_id"],
            event_id=patch_row["event_id"],
            target_file=patch_row["target_file"],
            target_function=patch_row["target_function"],
            patch_file=patch_row["patch_file"],
            unified_diff=patch_row["unified_diff"],
            patch_status=recheck.patch_status,
            change_summary=patch_row["change_summary_json"],
            patched_file_path=patch_row.get("patched_file_path"),
        )
        return RecheckResponse(job_id=job_id, status="success", recheck_result=recheck)

    def _materialize_patched_content(self, context: dict[str, Any], code_context: dict[str, Any], patched_snippet: str) -> str:
        original_content = code_context["full_content"]
        if code_context["resolved_path"] is None:
            return patched_snippet
        line_start = context["target"]["source_mapping"]["line_start"]
        line_end = context["target"]["source_mapping"]["line_end"]
        lines = original_content.splitlines()
        replacement_lines = patched_snippet.splitlines()
        start_idx = max(line_start - 1, 0)
        end_idx = min(line_end, len(lines))
        patched_lines = lines[:start_idx] + replacement_lines + lines[end_idx:]
        patched_content = "\n".join(patched_lines)
        if original_content.endswith("\n"):
            patched_content += "\n"
        return patched_content

    def _generate_patch_payload(
        self,
        job_id: str,
        context: dict[str, Any],
        code_context: dict[str, Any],
        strategy: PatchStrategy,
    ) -> dict[str, Any]:
        if self.settings.secure_coding_llm_provider.lower() == "mock":
            return {
                "patched_snippet": self._patch_snippet(context["attack_info"]["cwe_id"], code_context["snippet"]),
                "change_summary": {"security_fix": strategy.fix_actions[0]},
                "provider": "mock",
                "model": None,
            }
        if self.patch_client is None:
            raise LlmPatchClientError("LLM patch client was not initialized")
        prompt = self._build_llm_patch_prompt(context, code_context, strategy)
        prompt_path = self.artifact_root / "llm" / "prompts" / f"{job_id}.txt"
        write_text(prompt_path, prompt)
        response = self.patch_client.generate_patch_json(
            prompt=prompt,
            workdir=self.settings.workspace_root,
            schema=self._llm_patch_schema(),
        )
        response_path = self.artifact_root / "llm" / "responses" / f"{job_id}.json"
        write_text(response_path, response.raw_text)
        patched_snippet = response.payload.get("patched_snippet")
        if not isinstance(patched_snippet, str) or not patched_snippet.strip():
            raise LlmPatchClientError("LLM output did not contain a valid patched_snippet")
        change_summary = response.payload.get("change_summary") or {}
        if not isinstance(change_summary, dict):
            raise LlmPatchClientError("LLM output did not contain a valid change_summary object")
        return {
            "patched_snippet": patched_snippet,
            "change_summary": change_summary,
            "provider": response.provider,
            "model": response.model,
        }

    def _llm_patch_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "patched_snippet": {"type": "string"},
                "change_summary": {
                    "type": "object",
                    "properties": {"security_fix": {"type": "string"}},
                    "required": ["security_fix"],
                    "additionalProperties": True,
                },
            },
            "required": ["patched_snippet", "change_summary"],
            "additionalProperties": False,
        }

    def _build_llm_patch_prompt(self, context: dict[str, Any], code_context: dict[str, Any], strategy: PatchStrategy) -> str:
        return "\n".join(
            [
                "You are generating a secure code patch for one vulnerable code region.",
                "Return only a JSON object matching this shape:",
                '{"patched_snippet":"<string>","change_summary":{"security_fix":"<string>"}}',
                "Do not include markdown fences or explanation.",
                "Rules:",
                "- Preserve the existing function signature if visible in the snippet.",
                "- Keep the change minimal and limited to the vulnerable region.",
                "- Do not add new third-party dependencies.",
                "- Preserve existing response schema and unrelated behavior.",
                f"- CWE: {context['attack_info']['cwe_id']}",
                f"- Attack category: {context['attack_info']['category']}",
                f"- Target file: {context['target']['source_mapping']['file']}",
                f"- Target function: {context['target']['source_mapping']['function']}",
                f"- Line range: {context['target']['source_mapping']['line_start']}-{context['target']['source_mapping']['line_end']}",
                f"- Root cause: {strategy.root_cause}",
                "Required fix actions:",
                *[f"- {action}" for action in strategy.fix_actions],
                "Constraints:",
                *[f"- {key}={value}" for key, value in strategy.constraints.items()],
                "Original vulnerable snippet:",
                code_context["snippet"],
            ]
        )

    def _patch_snippet(self, cwe_id: str, snippet: str) -> str:
        if cwe_id == "CWE-89":
            return self._patch_sqli(snippet)
        if cwe_id == "CWE-79":
            return self._patch_xss(snippet)
        return self._patch_path_traversal(snippet)

    def _patch_sqli(self, snippet: str) -> str:
        lines = snippet.splitlines()
        patched, query_replaced, execute_replaced = [], False, False
        for line in lines:
            stripped = line.strip()
            indent = line[: len(line) - len(line.lstrip())]
            if not query_replaced and ("SELECT" in line and ("{" in line or ".format(" in line or "+ " in line)):
                patched.append(f'{indent}query = "SELECT * FROM users WHERE username = %s AND password = %s"')
                query_replaced = True
                continue
            if not execute_replaced and "execute(" in stripped and stripped.count(",") == 0:
                callee = stripped.split("execute(")[0] + "execute"
                patched.append(f"{indent}{callee}(query, (username, password))")
                execute_replaced = True
                continue
            patched.append(line)
        if not query_replaced:
            patched.append('    query = "SELECT * FROM users WHERE username = %s AND password = %s"')
        if not execute_replaced:
            patched.append("    result = db.execute(query, (username, password))")
        return "\n".join(patched)

    def _patch_xss(self, snippet: str) -> str:
        lines = snippet.splitlines()
        patched, inserted = [], False
        for line in lines:
            patched.append(line)
            if not inserted and ("request." in line or "content" in line or "user_input" in line):
                indent = line[: len(line) - len(line.lstrip())]
                patched.append(f"{indent}from html import escape")
                patched.append(f"{indent}safe_content = escape(content if 'content' in locals() else user_input, quote=True)")
                inserted = True
        if not inserted:
            patched.append("    from html import escape")
            patched.append("    safe_content = escape(user_input, quote=True)")
        return "\n".join(patched)

    def _patch_path_traversal(self, snippet: str) -> str:
        lines = snippet.splitlines()
        patched, inserted = [], False
        for line in lines:
            patched.append(line)
            if not inserted and ("open(" in line or "os.path.join" in line or "Path(" in line):
                indent = line[: len(line) - len(line.lstrip())]
                patched.extend(
                    [
                        f"{indent}from pathlib import Path",
                        f"{indent}base_dir = Path(BASE_DIR).resolve() if 'BASE_DIR' in globals() else Path('.').resolve()",
                        f"{indent}requested_path = (base_dir / filename).resolve()",
                        f"{indent}if base_dir not in requested_path.parents and requested_path != base_dir:",
                        f"{indent}    raise ValueError('Invalid path')",
                    ]
                )
                inserted = True
        if not inserted:
            patched.extend(
                [
                    "    from pathlib import Path",
                    "    base_dir = Path(BASE_DIR).resolve() if 'BASE_DIR' in globals() else Path('.').resolve()",
                    "    requested_path = (base_dir / filename).resolve()",
                    "    if base_dir not in requested_path.parents and requested_path != base_dir:",
                    "        raise ValueError('Invalid path')",
                ]
            )
        return "\n".join(patched)

    def _patched_content_is_safe(self, unified_diff: str) -> bool:
        sqli_markers = ["execute(query, (", "%s", "SELECT * FROM users WHERE username = ?", "params=", ".bindparams("]
        xss_markers = ["escape(", "html.escape", "markupsafe", "bleach.clean"]
        path_markers = ["resolve()", "abspath(", "realpath(", "normpath(", "relative_to("]
        return bool(
            any(marker in unified_diff for marker in sqli_markers)
            or any(marker in unified_diff for marker in xss_markers)
            or (
                any(marker in unified_diff for marker in path_markers)
                and ("Invalid path" in unified_diff or "base_dir" in unified_diff or "startswith(" in unified_diff)
            )
        )
