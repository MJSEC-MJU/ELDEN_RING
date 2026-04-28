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
| `POST /api/llm/login/{session_id}/code` | Submit Claude OAuth paste-back (`code#state` or full callback URL) |
| `POST /api/llm/login/{session_id}/cancel` | Terminate a stuck/abandoned OAuth login subprocess |
| `POST /api/llm/simulate?provider=codex` | Run a real LLM patch smoke test, then replay dashboard phase events |

## Claude OAuth flow inside a pod

`claude auth login` always builds **two** authorize URLs from the same
`code_challenge` + `state`:

* manual: `redirect_uri=https://platform.claude.com/oauth/code/callback`
* local:  `redirect_uri=http://localhost:<port>/callback`

Token-exchange picks `redirect_uri` based on whether its loopback listener
received a callback. If the user authorises with the manual URL but we then
forward the resulting code to the local listener, the redirect_uris don't
match and Anthropic returns HTTP 400.

The dashboard fixes this by surfacing the **local** URL alongside the manual
one in the session output. The flow is:

1. backend spawns `claude auth login`; CLI prints the manual URL on stdout
   and binds an IPv6 loopback HTTP listener.
2. backend walks `/proc/<pid>/net/tcp6` to find the listener port, rebuilds
   the same authorize URL with `redirect_uri=http://localhost:<port>/callback`,
   and appends it to the session output.
3. user opens the **local** URL in their browser, signs in + approves.
   Anthropic redirects to `http://localhost:<port>/callback?code=…&state=…`
   which fails to load on the user's machine — the listener lives in the pod.
4. user copies the address-bar URL into the dashboard. Backend parses
   `code`/`state` and forwards them to `http://[::1]:<port>/callback…`.
5. CLI's listener completes token exchange with the matching local-mode
   `redirect_uri` → HTTP 200, login complete.

## Environment

| Variable | Default | Description |
|---|---|---|
| `MONITOR_LLM_PROVIDER` | `codex` | Default backend provider |
| `MONITOR_CODEX_COMMAND` | `codex` | Codex CLI command/path |
| `MONITOR_CLAUDE_COMMAND` | `claude` | Claude CLI command/path |
| `MONITOR_LLM_TIMEOUT_SEC` | `180` | Patch smoke CLI timeout |
