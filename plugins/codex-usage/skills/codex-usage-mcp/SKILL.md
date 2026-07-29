---
name: codex-usage-mcp
description: Use the local Codex Usage MCP server whenever the user asks about Codex quotas, remaining or used capacity, token usage, credits, reset times, usage history, burn rate, forecasts, or whether to defer usage-heavy work.
---

# Codex Usage MCP

Use `codex-usage` at `http://127.0.0.1:8797/mcp` as the authoritative source
for current Codex account usage. Do not substitute memory, estimates, session
log scraping, or web search when this server is available.

Prefer:

- `get_usage_summary` for current limits, amounts used/remaining, credits,
  account token usage, and reset times;
- `get_usage_heuristics` for burn rate, trend, forecast, posture, and work
  recommendations;
- `get_usage_history` for prior locally captured snapshots;
- `get_source_status` for freshness, readiness, and disclosure caveats;
- `refresh_usage` when an explicitly fresh provider read is required.
- `register_quark_work` to queue one checkpointable project/thread workload;
- `get_quark_work_queue` and `get_quark_project_effort` for scheduling and
  estimate-versus-actual evidence;
- `plan_quark_work_cycle` for reserve-aware planning. Keep `execute=false`
  unless the user has authorized starting the registered Codex work.

Codex quota windows often disclose only percentages. Report absolute capacity
as unknown unless the MCP result includes an individual limit or credit
balance. Never convert token counts into quota units.

The upstream local app server uses the existing Codex login. Never request,
read, print, or return `auth.json` or tokens.

When MCP data affects an answer, include brief evidence naming the server and
tool, such as `Codex usage MCP evidence: get_usage_summary`.

Quark's default hard reserve is 15 percentage points with a 2-point uncertainty
margin and 5-point bounded work slices. It should allocate all capacity above
that floor when registered checkpointable work exists. Normal pause/resume is
between completed `codex exec resume` turns; interruption is an abort and must
leave the work in `reconcile_required`.

If unavailable, say that live usage could not be verified and provide
`codex mcp get codex-usage` plus the loopback health URL as remediation. Do not
present remembered values as current.
