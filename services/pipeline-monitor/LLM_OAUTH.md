# Pipeline Monitor LLM OAuth

The dashboard top bar includes an **LLM OAuth** control.

1. Select `Codex` or `Claude`.
2. Click `OAuth Login` if the status is `login needed`.
3. Complete the CLI device/browser login shown in the panel.
4. Click `LLM Smoke`.

`LLM Smoke` calls the selected CLI for a real patch generation against a CWE-89 sample, then replays synthetic Phase 1 -> Phase 2 -> Phase 3 -> Phase 4 events into the dashboard. The incident modal shows the LLM provider, security fix, generated diff, and patched snippet.

## API

| Endpoint | Description |
|---|---|
| `GET /api/llm/status` | Codex/Claude CLI availability and OAuth status |
| `POST /api/llm/login?provider=codex` | Start a Codex/Claude OAuth device/browser login session |
| `GET /api/llm/login/{session_id}` | Poll OAuth login output/status |
| `POST /api/llm/simulate?provider=codex` | Run a real LLM patch smoke test, then replay dashboard phase events |

## Environment

| Variable | Default | Description |
|---|---|---|
| `MONITOR_LLM_PROVIDER` | `codex` | Default backend provider |
| `MONITOR_CODEX_COMMAND` | `codex` | Codex CLI command/path |
| `MONITOR_CLAUDE_COMMAND` | `claude` | Claude CLI command/path |
| `MONITOR_LLM_TIMEOUT_SEC` | `180` | Patch smoke CLI timeout |
