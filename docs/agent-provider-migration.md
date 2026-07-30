# Agent Provider Migration

Codex remains the compatibility provider while provider-neutral interfaces are
adopted. Legacy Codex routes, resource identifiers, CSV imports, payloads, and
entry points remain available for one migration cycle.

## Compatibility window

New integrations should use `/agent-providers`, `/agent-instances`,
`/agent-sessions`, `/agent-dispatches`, `/agent-checkpoints`,
`/agent-recovery`, `/agent-handoffs`, and `/agent-failover`. The exact legacy
alias `POST /codex-projects/discover-threads` remains during the compatibility
window and emits deprecation and successor-link headers. Legacy
`thread.codex.*` resources link to normalized `session.codex.*` records without
deleting or rewriting the original CSV data.

Codex-specific usage observation remains `svc.mcp.codex-usage`; it is not
renamed into a universal quota source. Legacy Quark Codex payloads retain their
exact fields while generic provider work uses explicit provider, session,
epoch, limit, and usage-unit bindings.

## Migration sequence

1. Keep the committed primary selection on `codex`.
2. Inspect `agent-providers` and `agent-instances` readiness.
3. Discover/import Codex sessions and verify legacy resource links.
4. Move callers to generic session, dispatch, checkpoint, and recovery routes.
5. Configure only workspace, model, credential-reference, and verified
   `executable_path` overrides locally. Provider and fallback selection remain
   committed configuration.
6. Contract-test the replacement adapter with fake executables.
7. Stage the exact manual-handoff approval, then hand off in a disposable
   instance.
8. Enable controlled failover only after persisted policy, health, checkpoint,
   risk, readiness, decision, and recovery gates are verified.

Claude is eligible for tested replacement-driver workflows but is not described
as live-proven. Qwen Code, Mistral Vibe, and Antigravity remain recognized and
live-unavailable until verified programmatic interfaces exist.

## Rollback

Before promotion, a failed import leaves the outgoing provider fenced. During
rollback, Overseer cancels the exact incoming external session and resumes the
outgoing provider only after terminal cancellation is externally verified.
If cancellation is unsupported, fails, times out, or is ambiguous, keep the
instance paused and reconcile it under a separate authorization.

To roll back configuration for the next startup, restore
`primary_provider_id` to `codex`, remove unapproved fallback entries, and keep
the legacy registry intact. Do not edit an active epoch or delete handoff,
dispatch, checkpoint, decision, or execution evidence. Active instances change
authority only through recovery, manual handoff, or controlled failover.

After one migration cycle, removal of a compatibility alias requires a
separate deprecation decision, updated callers, and regression evidence. This
release does not remove legacy surfaces.
