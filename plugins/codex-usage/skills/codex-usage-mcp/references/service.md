# Service Reference

- MCP server: `codex-usage`
- endpoint: `http://127.0.0.1:8797/mcp`
- health: `http://127.0.0.1:8797/health`
- upstream: local `codex app-server --stdio`
- authentication: existing Codex login, with no credential files exposed
- tools: refresh, summary, history, heuristics, source status, Quark work
  registration, queue, reserve-aware cycle planning/execution, project effort
- fallback: report unavailable/stale state; never guess current usage
