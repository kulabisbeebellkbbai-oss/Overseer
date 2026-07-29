# Codex Usage MCP

The Codex Usage MCP exposes the usage information available from the local
authenticated Codex app server and records metadata-only snapshots for trends.
It does not read authentication files, prompts, tool output, or conversation
content.

## Data

- every rate-limit bucket returned by `account/rateLimits/read`;
- primary and secondary used/remaining percentages and reset times;
- plan, reached-limit, spend-control, credit, and individual-limit fields;
- lifetime and daily token information returned by `account/usage/read`;
- append-only local snapshot history;
- burn-rate forecasts, daily-token trends, a capacity posture, and a work
  recommendation.

Codex generally discloses quota usage as a percentage. The server reports
percentage capacity as percentage capacity and leaves absolute capacity unknown
unless Codex supplies an individual limit or credit balance. Token counts are
never treated as interchangeable with weighted quota percentages.

## Run

```bash
python -m overseer.codex_usage_mcp --host 127.0.0.1 --port 8797 \
  --db state/codex-usage.sqlite3
```

Endpoints:

- MCP: `http://127.0.0.1:8797/mcp`
- health: `http://127.0.0.1:8797/health`

The server rejects non-loopback binds. Remote publication requires a separate,
explicitly approved Protected Service Gateway plan.

## Tools

- `refresh_usage`
- `get_usage_summary`
- `get_usage_history`
- `get_usage_heuristics`
- `get_source_status`
- `register_quark_work`
- `get_quark_work_queue`
- `plan_quark_work_cycle`
- `get_quark_project_effort`

`refresh_usage` reads provider state and writes only a normalized local
snapshot. It does not consume reset credits or mutate the Codex account.

`plan_quark_work_cycle` is dry-run by default. `execute=true` starts at most the
configured number of bounded `codex exec resume` turns and therefore performs a
host mutation. Quark preserves its reserve floor and only executes work that
was explicitly registered.
