from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class LlmOAuthError(RuntimeError):
    pass


@dataclass
class LoginSession:
    session_id: str
    provider: str
    command: list[str]
    started_at: float = field(default_factory=time.time)
    status: str = "running"
    output: list[str] = field(default_factory=list)
    returncode: int | None = None
    # Live subprocess handle so we can forward an OAuth code back into the CLI.
    # Required for providers like claude-code whose login flow only completes
    # when its loopback `/callback` listener receives the authorize redirect.
    process: subprocess.Popen | None = field(default=None, repr=False)
    awaiting_code: bool = False
    submitted_code: bool = False


_LOGIN_SESSIONS: dict[str, LoginSession] = {}
_LOGIN_LOCK = threading.Lock()


def llm_status() -> dict[str, Any]:
    return {
        "active_provider": os.getenv("MONITOR_LLM_PROVIDER", "codex"),
        "providers": {
            "codex": _codex_status(),
            "claude": _claude_status(),
        },
    }


def start_login(provider: str) -> dict[str, Any]:
    normalized = _normalize_provider(provider)
    status = _provider_status(normalized)
    if status["authenticated"]:
        return {"status": "already_authenticated", "provider": normalized, "session_id": None, "output": status["detail"]}
    if not status["available"]:
        raise LlmOAuthError(status["detail"])

    command = _login_command(normalized)
    session_id = f"login-{uuid.uuid4().hex[:10]}"
    session = LoginSession(session_id=session_id, provider=normalized, command=command)
    with _LOGIN_LOCK:
        _cleanup_sessions_locked()
        _LOGIN_SESSIONS[session_id] = session

    thread = threading.Thread(target=_run_login_session, args=(session,), daemon=True)
    thread.start()
    return {
        "status": "started",
        "provider": normalized,
        "session_id": session_id,
        "command": " ".join(command),
        "output": "",
    }


def get_login_session(session_id: str) -> dict[str, Any]:
    with _LOGIN_LOCK:
        session = _LOGIN_SESSIONS.get(session_id)
        if not session:
            raise LlmOAuthError("Unknown OAuth login session")
        return {
            "session_id": session.session_id,
            "provider": session.provider,
            "status": session.status,
            "returncode": session.returncode,
            "output": _sanitize_text("\n".join(session.output[-120:])),
            "awaiting_code": session.awaiting_code and not session.submitted_code,
            "submitted_code": session.submitted_code,
        }


def submit_login_code(session_id: str, code: str) -> dict[str, Any]:
    """Forward an OAuth callback to the running CLI's loopback listener.

    Mechanism (claude-code, verified against the 2.1.121 binary):
      1. `claude.startOAuthFlow` builds *two* authorize URLs from the same
         `code_challenge` + `state`: a manual one
         (`redirect_uri=https://platform.claude.com/oauth/code/callback`) and a
         local one (`redirect_uri=http://localhost:<port>/callback`).
      2. Token-exchange's `redirect_uri` is decided by `!Y` where
         `Y = listener.hasPendingResponse()`. So it must match whichever URL the
         browser actually authorised with — otherwise Anthropic returns 400
         "Token exchange failed".
      3. The CLI prints only the *manual* URL on stdout. If the user grabs the
         code off platform.claude.com (manual) and we forward it to the local
         listener, the listener sets `Y=true` and the exchange uses the local
         redirect_uri — which doesn't match the manual one used at auth, so 400.
      4. Fix: we surface the *local* URL too (built by swapping the redirect_uri
         on the printed URL once we discover the listener's port). The user
         visits the local URL, signs in, and the browser then tries to load
         `http://localhost:<port>/callback?...` (which fails on a remote pod —
         expected, the address-bar URL is what we need). They paste that URL
         here, we forward it to the listener, and the redirect_uris line up.

    For codex's device-auth flow this endpoint is a no-op."""
    raw = (code or "").strip()
    if not raw:
        raise LlmOAuthError("OAuth code cannot be empty")
    with _LOGIN_LOCK:
        session = _LOGIN_SESSIONS.get(session_id)
        if not session:
            raise LlmOAuthError("Unknown OAuth login session")
        if session.status != "running":
            raise LlmOAuthError(f"Login session is no longer running (status={session.status})")
        proc = session.process

    auth_code, state_param = _parse_oauth_paste(raw)
    if not auth_code or not state_param:
        raise LlmOAuthError(
            "Could not parse 'code#state' or callback URL from input — "
            "open the local OAuth URL shown above, sign in, then paste the "
            "URL the browser tried to load (it'll be http://localhost:<port>/callback?code=...&state=...)"
        )

    if session.provider == "claude":
        port = _find_claude_listener_port(proc)
        if not port:
            raise LlmOAuthError(
                "Could not locate the claude CLI's loopback OAuth listener — "
                "the login session may have already exited"
            )
        delivered, detail = _forward_to_local_callback(port, auth_code, state_param)
        with _LOGIN_LOCK:
            session.submitted_code = True
            session.awaiting_code = False
            session.output.append(
                f"[dashboard] forwarded OAuth callback to claude listener "
                f"(port={port}, code_len={len(auth_code)}, state_len={len(state_param)}, "
                f"http={detail})"
            )
            return {
                "session_id": session.session_id,
                "provider": session.provider,
                "status": session.status,
                "submitted_code": True,
                "callback_port": port,
                "callback_http": detail,
                "delivered": delivered,
            }

    # Fallback for any other provider that *does* read stdin (kept for forward
    # compatibility — none of the bundled CLIs use this path today).
    if proc is None or proc.stdin is None or proc.stdin.closed:
        raise LlmOAuthError("Login session does not accept code input")
    try:
        proc.stdin.write(raw + "\n")
        proc.stdin.flush()
    except (BrokenPipeError, OSError) as exc:
        raise LlmOAuthError(f"Failed to deliver OAuth code to CLI: {exc}") from exc
    with _LOGIN_LOCK:
        session.submitted_code = True
        session.awaiting_code = False
        session.output.append(f"[dashboard] submitted OAuth code via stdin (len={len(raw)})")
        return {
            "session_id": session.session_id,
            "provider": session.provider,
            "status": session.status,
            "submitted_code": True,
        }


def _find_claude_listener_port(proc: subprocess.Popen | None) -> int | None:
    """Walk /proc/<pid>/fd to find the loopback HTTP listener claude opens for OAuth.
    Returns the port (host byte order) or None if the listener has already closed."""
    if proc is None or proc.pid is None or proc.pid <= 0:
        return None
    pid = proc.pid
    try:
        sock_inodes: set[str] = set()
        task_root = f"/proc/{pid}/task"
        thread_ids = os.listdir(task_root) if os.path.isdir(task_root) else [str(pid)]
        for tid in thread_ids:
            fdroot = f"/proc/{pid}/task/{tid}/fd"
            if not os.path.isdir(fdroot):
                fdroot = f"/proc/{pid}/fd"
            try:
                for fd in os.listdir(fdroot):
                    try:
                        target = os.readlink(os.path.join(fdroot, fd))
                    except OSError:
                        continue
                    if target.startswith("socket:["):
                        sock_inodes.add(target.split("[", 1)[1].rstrip("]"))
            except FileNotFoundError:
                continue
        if not sock_inodes:
            return None
        for tcp_path in ("/proc/net/tcp", "/proc/net/tcp6"):
            try:
                with open(tcp_path) as f:
                    rows = f.readlines()[1:]
            except FileNotFoundError:
                continue
            for row in rows:
                cols = row.split()
                if len(cols) < 10:
                    continue
                if cols[3] != "0A":  # 0A = LISTEN
                    continue
                if cols[9] not in sock_inodes:
                    continue
                local = cols[1]
                try:
                    port = int(local.split(":")[1], 16)
                except (IndexError, ValueError):
                    continue
                if port:
                    return port
    except FileNotFoundError:
        return None
    return None


def _forward_to_local_callback(port: int, code: str, state: str) -> tuple[bool, str]:
    """GET claude's loopback listener at /callback, which is wired to set
    `Y=true` so token-exchange uses the local-mode redirect_uri (which matches
    the local-mode auth URL the user is asked to visit)."""
    qs = urllib.parse.urlencode({"code": code, "state": state})
    last_detail = "no-attempt"
    for host in ("[::1]", "127.0.0.1"):
        url = f"http://{host}:{port}/callback?{qs}"
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=8) as resp:
                last_detail = f"{host}={resp.status}"
                if 200 <= resp.status < 400:
                    return True, last_detail
        except urllib.error.HTTPError as e:
            # 4xx with a body still means the listener handled the request — claude's
            # token-exchange may yet succeed/fail; either way we delivered the code.
            last_detail = f"{host}={e.code}"
            return True, last_detail
        except (urllib.error.URLError, ConnectionError, OSError) as e:
            last_detail = f"{host}=err:{type(e).__name__}"
            continue
    return False, last_detail


_AUTH_URL_RE = re.compile(
    r"https?://[^\s]*?/oauth/authorize\?[^\s]*",
    re.IGNORECASE,
)


def _local_oauth_url(manual_url: str, port: int) -> str | None:
    """Rebuild the same authorize URL with `redirect_uri=http://localhost:<port>/callback`.
    Everything else (state, code_challenge, client_id) is preserved, so the resulting
    code Anthropic mints is bound to the local listener — and our forwarder won't
    trip the redirect_uri-mismatch 400."""
    try:
        parsed = urllib.parse.urlparse(manual_url)
    except Exception:
        return None
    if not parsed.scheme or not parsed.netloc:
        return None
    qs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    new_qs: list[tuple[str, str]] = []
    saw_redirect = False
    for k, v in qs:
        if k == "redirect_uri":
            new_qs.append((k, f"http://localhost:{port}/callback"))
            saw_redirect = True
        else:
            new_qs.append((k, v))
    if not saw_redirect:
        new_qs.append(("redirect_uri", f"http://localhost:{port}/callback"))
    new_query = urllib.parse.urlencode(new_qs)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))


def _augment_claude_session_with_local_url(session: LoginSession) -> None:
    """Once claude has printed the manual URL and bound its loopback listener,
    compute the matching *local* URL and surface it in the session output. The
    dashboard renders it as the primary action so users skip the manual flow
    that we have no way to feed back into the CLI from outside."""
    if session.provider != "claude":
        return
    if any("[dashboard] Local OAuth URL" in line for line in session.output):
        return
    manual_url: str | None = None
    for line in session.output:
        m = _AUTH_URL_RE.search(line)
        if m and "redirect_uri" in m.group(0):
            manual_url = m.group(0)
            break
    if not manual_url:
        return
    port = _find_claude_listener_port(session.process)
    if not port:
        return
    local_url = _local_oauth_url(manual_url, port)
    if not local_url:
        return
    session.output.append(
        "[dashboard] Local OAuth URL (use this one — paste-back actually works):"
    )
    session.output.append(local_url)


def _parse_oauth_paste(text: str) -> tuple[str, str]:
    """Extract (code, state) from one of:
      * `<code>#<state>`  (what platform.claude.com displays)
      * full callback URL `https://.../callback?code=...&state=...`
      * raw query string `code=...&state=...`
    """
    text = text.strip()
    # Full URL
    if text.startswith(("http://", "https://")):
        try:
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(text).query)
        except Exception:
            return "", ""
        return (qs.get("code", [""])[0], qs.get("state", [""])[0])
    # Bare query string
    if "code=" in text and "state=" in text and "#" not in text:
        qs = urllib.parse.parse_qs(text.lstrip("?&"))
        return (qs.get("code", [""])[0], qs.get("state", [""])[0])
    # `code#state`
    if "#" in text:
        code, _, state = text.partition("#")
        return code.strip(), state.strip()
    return "", ""


def cancel_login_session(session_id: str) -> dict[str, Any]:
    """Terminate a running OAuth login subprocess.

    Used to recover from claude/codex CLIs that are stuck waiting for an
    auth event that will never arrive (e.g. user closed browser tab, or the
    polling backend never received the user's approval). Without this,
    a stuck claude process would sit in `do_epoll_wait` forever, holding a
    PID slot in the pod."""
    with _LOGIN_LOCK:
        session = _LOGIN_SESSIONS.get(session_id)
        if not session:
            raise LlmOAuthError("Unknown OAuth login session")
        proc = session.process
    if proc is not None and proc.poll() is None:
        try:
            proc.terminate()
        except Exception:
            pass
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except Exception:
                pass
    with _LOGIN_LOCK:
        if session.status == "running":
            session.status = "cancelled"
            session.output.append("[dashboard] login session cancelled")
        session.awaiting_code = False
        return {
            "session_id": session.session_id,
            "provider": session.provider,
            "status": session.status,
        }


def cancel_all_running_sessions() -> int:
    """Best-effort cleanup of any stuck login subprocesses.

    Invoked at FastAPI startup so a redeploy doesn't carry over orphan
    `claude auth login` processes from the previous pod generation."""
    with _LOGIN_LOCK:
        ids = [sid for sid, s in _LOGIN_SESSIONS.items() if s.status == "running"]
    cleaned = 0
    for sid in ids:
        try:
            cancel_login_session(sid)
            cleaned += 1
        except LlmOAuthError:
            pass
    return cleaned


def run_patch_smoke(provider: str) -> dict[str, Any]:
    normalized = _normalize_provider(provider)
    status = _provider_status(normalized)
    if not status["available"]:
        raise LlmOAuthError(status["detail"])
    if not status["authenticated"]:
        raise LlmOAuthError(f"{normalized} OAuth session is not authenticated")
    if normalized == "codex":
        return _run_codex_patch_smoke()
    if normalized == "claude":
        return _run_claude_patch_smoke()
    raise LlmOAuthError(f"Unsupported LLM provider: {provider}")


def _normalize_provider(provider: str) -> str:
    value = (provider or "codex").lower().strip()
    if value in {"codex", "openai"}:
        return "codex"
    if value in {"claude", "claude_code", "claude-code", "anthropic"}:
        return "claude"
    raise LlmOAuthError(f"Unsupported LLM provider: {provider}")


def _provider_status(provider: str) -> dict[str, Any]:
    if provider == "codex":
        return _codex_status()
    if provider == "claude":
        return _claude_status()
    raise LlmOAuthError(f"Unsupported LLM provider: {provider}")


def _command_parts(command: str) -> list[str]:
    return [command]


def _resolve_command(command: str) -> list[str] | None:
    parts = _command_parts(command)
    executable = parts[0]
    if Path(executable).exists():
        return parts
    resolved = shutil.which(executable)
    if resolved:
        return [resolved, *parts[1:]]
    return None


def _codex_command() -> list[str] | None:
    return _resolve_command(os.getenv("MONITOR_CODEX_COMMAND", "codex"))


def _claude_command() -> list[str] | None:
    return _resolve_command(os.getenv("MONITOR_CLAUDE_COMMAND", "claude"))


def _codex_status() -> dict[str, Any]:
    command = _codex_command()
    if not command:
        return _status_payload(False, False, "Codex CLI not found in this monitor runtime", "codex login --device-auth")
    completed = _run(command + ["login", "status"], timeout=12)
    text = _sanitize_text(f"{completed.stdout}\n{completed.stderr}".strip())
    authenticated = completed.returncode == 0 and "Logged in" in text
    return _status_payload(True, authenticated, text or f"exit={completed.returncode}", "codex login --device-auth")


def _claude_status() -> dict[str, Any]:
    command = _claude_command()
    if not command:
        return _status_payload(False, False, "Claude CLI not found in this monitor runtime", "claude auth login")
    completed = _run(command + ["auth", "status"], timeout=12)
    text = _sanitize_text(f"{completed.stdout}\n{completed.stderr}".strip())
    authenticated = False
    detail = text or f"exit={completed.returncode}"
    try:
        payload = json.loads(completed.stdout)
        authenticated = bool(payload.get("loggedIn"))
        detail = json.dumps(
            {
                "loggedIn": authenticated,
                "authMethod": payload.get("authMethod"),
                "apiProvider": payload.get("apiProvider"),
                "subscriptionType": payload.get("subscriptionType"),
            },
            ensure_ascii=False,
        )
    except json.JSONDecodeError:
        authenticated = completed.returncode == 0 and "logged" in text.lower()
    return _status_payload(True, authenticated, detail, "claude auth login")


def _status_payload(available: bool, authenticated: bool, detail: str, login_command: str) -> dict[str, Any]:
    return {
        "available": available,
        "authenticated": authenticated,
        "detail": detail,
        "login_command": login_command,
    }


def _login_command(provider: str) -> list[str]:
    if provider == "codex":
        command = _codex_command()
        if not command:
            raise LlmOAuthError("Codex CLI not found")
        return command + ["login", "--device-auth"]
    if provider == "claude":
        command = _claude_command()
        if not command:
            raise LlmOAuthError("Claude CLI not found")
        return command + ["auth", "login"]
    raise LlmOAuthError(f"Unsupported LLM provider: {provider}")


# Heuristic markers that mean "the CLI is now waiting for the user to paste back
# the OAuth callback code." Any line containing one of these strings will flip the
# session into awaiting_code=True so the dashboard can show an input field.
_OAUTH_CODE_PROMPTS = (
    "paste the code",
    "paste code",
    "enter the code",
    "enter code",
    "/oauth/code/callback",
    "authorization code:",
    "auth code:",
    "code:",
    # claude prints these *before* its loopback listener will see anything
    "if the browser didn't open",
    "opening browser to sign in",
)


def _run_login_session(session: LoginSession) -> None:
    try:
        process = subprocess.Popen(
            session.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        with _LOGIN_LOCK:
            session.process = process
        assert process.stdout is not None
        for line in process.stdout:
            stripped = line.rstrip()
            with _LOGIN_LOCK:
                session.output.append(stripped)
                low = stripped.lower()
                if not session.submitted_code and any(p in low for p in _OAUTH_CODE_PROMPTS):
                    session.awaiting_code = True
            # Once claude has printed its manual auth URL, surface the matching
            # *local* URL too — that's the one the user actually needs to visit
            # so the eventual paste-back lines up with the local-mode redirect_uri
            # in token-exchange. The listener port only exists *after* the bind,
            # which is essentially immediate but we still defer until we see
            # the URL line on stdout.
            if session.provider == "claude" and "/oauth/authorize" in stripped:
                # Give the listener a beat to bind before walking /proc.
                time.sleep(0.1)
                with _LOGIN_LOCK:
                    _augment_claude_session_with_local_url(session)
        returncode = process.wait(timeout=300)
        with _LOGIN_LOCK:
            session.returncode = returncode
            session.status = "completed" if returncode == 0 else "failed"
            session.awaiting_code = False
    except subprocess.TimeoutExpired:
        with _LOGIN_LOCK:
            session.status = "timeout"
            session.output.append("OAuth login timed out after 300 seconds.")
            session.awaiting_code = False
    except Exception as exc:
        with _LOGIN_LOCK:
            session.status = "failed"
            session.output.append(str(exc))
            session.awaiting_code = False


def _cleanup_sessions_locked() -> None:
    now = time.time()
    stale = [sid for sid, session in _LOGIN_SESSIONS.items() if now - session.started_at > 1800]
    for sid in stale:
        _LOGIN_SESSIONS.pop(sid, None)


def _run_codex_patch_smoke() -> dict[str, Any]:
    command = _codex_command()
    if not command:
        raise LlmOAuthError("Codex CLI not found")
    with tempfile.TemporaryDirectory(prefix="elden-monitor-codex-") as tmp_dir:
        tmp_root = Path(tmp_dir)
        schema_path = tmp_root / "schema.json"
        output_path = tmp_root / "output.json"
        schema_path.write_text(json.dumps(_patch_schema()), encoding="utf-8")
        completed = _run(
            command
            + [
                "exec",
                "--skip-git-repo-check",
                "-C",
                str(tmp_root),
                "--sandbox",
                "read-only",
                "--output-schema",
                str(schema_path),
                "-o",
                str(output_path),
                "-",
            ],
            input_text=_patch_prompt(),
            timeout=int(os.getenv("MONITOR_LLM_TIMEOUT_SEC", "180")),
        )
        if completed.returncode != 0:
            raise LlmOAuthError(_sanitize_text(completed.stderr or completed.stdout or "Codex patch smoke failed"))
        raw_text = output_path.read_text(encoding="utf-8") if output_path.exists() else completed.stdout
        payload = _parse_json_payload(raw_text)
        return _patch_result_payload("codex", payload, raw_text)


def _run_claude_patch_smoke() -> dict[str, Any]:
    command = _claude_command()
    if not command:
        raise LlmOAuthError("Claude CLI not found")
    # Match the codex path: feed the vulnerable code via stdin (safe escaping for the
    # SQL/quote-laden snippet), and let claude-code 2.0.45+'s `--json-schema` enforce
    # the response shape so we don't have to scrape JSON out of free-form text.
    completed = _run(
        command
        + [
            "-p",
            "--permission-mode", "dontAsk",
            "--tools", "",
            "--output-format", "json",
            "--json-schema", json.dumps(_patch_schema()),
        ],
        input_text=_patch_prompt(),
        timeout=int(os.getenv("MONITOR_LLM_TIMEOUT_SEC", "180")),
    )
    if completed.returncode != 0:
        raise LlmOAuthError(_sanitize_text(completed.stderr or completed.stdout or "Claude patch smoke failed"))
    payload = _extract_claude_structured_output(completed.stdout)
    return _patch_result_payload("claude", payload, completed.stdout)


def _extract_claude_structured_output(raw: str) -> dict[str, Any]:
    """Claude Code `--output-format json` returns a metadata wrapper; the schema-validated
    object is in `structured_output` (preferred) or nested in `result` for older builds.
    Fall back to best-effort JSON extraction if the wrapper shape changes."""
    try:
        wrapper = json.loads(raw)
    except json.JSONDecodeError:
        return _parse_json_payload(raw)
    if isinstance(wrapper, dict):
        structured = wrapper.get("structured_output")
        if isinstance(structured, dict):
            return structured
        result = wrapper.get("result")
        if isinstance(result, dict):
            return result
        if isinstance(result, str) and result.strip():
            return _parse_json_payload(result)
    return _parse_json_payload(raw)


def _patch_result_payload(provider: str, payload: dict[str, Any], raw_text: str) -> dict[str, Any]:
    patched_snippet = payload.get("patched_snippet")
    change_summary = payload.get("change_summary")
    if not isinstance(patched_snippet, str) or not patched_snippet.strip():
        raise LlmOAuthError("LLM output did not contain patched_snippet")
    if not isinstance(change_summary, dict):
        raise LlmOAuthError("LLM output did not contain change_summary")
    return {
        "provider": provider,
        "patched_snippet": patched_snippet,
        "change_summary": change_summary,
        "raw_preview": _sanitize_text(raw_text)[:2000],
    }


def _patch_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "patched_snippet": {"type": "string"},
            "change_summary": {
                "type": "object",
                "properties": {"security_fix": {"type": "string"}},
                "required": ["security_fix"],
                "additionalProperties": False,
            },
        },
        "required": ["patched_snippet", "change_summary"],
        "additionalProperties": False,
    }


def _patch_prompt() -> str:
    return "\n".join(
        [
            "Generate a minimal secure patch for this vulnerable Python function.",
            "Return only JSON with patched_snippet and change_summary.security_fix.",
            "Preserve the function signature and response behavior.",
            "CWE: CWE-89 SQL Injection.",
            "Required fix: replace SQL string interpolation with parameterized binding.",
            "Original vulnerable snippet:",
            "def authenticate(username, password, db):",
            "    query = f\"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'\"",
            "    result = db.execute(query)",
            "    return result",
        ]
    )


def _run(args: list[str], *, timeout: int, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            args,
            input=input_text,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise LlmOAuthError(f"Command timed out after {timeout}s: {' '.join(args[:3])}") from exc


def _parse_json_payload(raw_text: str) -> dict[str, Any]:
    text = raw_text.strip()
    candidates = [text]
    if "```" in text:
        parts = text.split("```")
        for idx in range(1, len(parts), 2):
            chunk = parts[idx]
            if "\n" in chunk:
                chunk = chunk.split("\n", 1)[1]
            candidates.append(chunk.strip())
    decoder = json.JSONDecoder()
    for candidate in candidates:
        try:
            payload = json.loads(candidate)
            if isinstance(payload, dict):
                return payload
        except json.JSONDecodeError:
            pass
        for start, char in enumerate(candidate):
            if char != "{":
                continue
            try:
                payload, end = decoder.raw_decode(candidate[start:])
            except json.JSONDecodeError:
                continue
            if candidate[start + end :].strip():
                continue
            if isinstance(payload, dict):
                return payload
    raise LlmOAuthError("LLM output was not valid JSON")


def _sanitize_text(value: str) -> str:
    redacted = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", value or "")
    redacted = re.sub(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", "<redacted-email>", redacted)
    redacted = re.sub(r"(?i)(api[_-]?key|token|secret)[=:]\s*\S+", r"\1=<redacted>", redacted)
    return redacted.strip()
