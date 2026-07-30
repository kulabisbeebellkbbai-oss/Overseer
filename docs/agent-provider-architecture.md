# Agent Provider Architecture

Overseer has one primary driver per instance. Codex is the compatibility
provider, but a configured Claude adapter can replace it through an approved
manual handoff. Qwen Code, Mistral Vibe, and Antigravity are recognized
providers whose live readiness remains unavailable until a local programmatic
interface is verified.

The deterministic Overseer core remains authoritative for policy, approvals,
claims, secrets, scheduling, and durable state. A provider capability describes
technical ability; it does not authorize an action. DS9 crew roles are
responsibility and approval domains, never provider accounts.

## Configuration and readiness

`config/agent-providers.json` is the committed provider catalog and instance
selection. An instance records `primary_provider_id`, optional approved
`fallback_provider_ids`, and the workspace. Provider selection is committed
configuration in the current contract. `--agent-registry-local` may point to a
machine-local override, but a local override cannot change provider selection:
it cannot change `primary_provider_id`, fallback order, or provider identity.
Local overrides are limited to workspace, model profile, credential references,
and `executable_path`; they never contain an inline credential value.
Credential references are resolved outside committed configuration and
persisted agent records.

Editing either registry while an instance is active does not replace its
driver. Selection is activated only at startup or through a lifecycle
operation. Inspect configured and detected state with:

```bash
PYTHONPATH=src python3 -m overseer.cli agent-providers
PYTHONPATH=src python3 -m overseer.cli agent-instances --store state/overseer.sqlite3
```

Provider status reports availability, the adapter identifier, transports,
capabilities, and health/usage source identifiers. Instance status reports the
active driver epoch, current-driver and failover-policy readiness, the current
checkpoint reference, and transition state. Missing executables, missing
capabilities, or absent failover policy evidence are blockers, not degraded
success.

## Sessions, epochs, dispatch, and checkpoints

A provider session is external continuity. A driver epoch is the immutable
authority binding for one provider/session generation. Dispatch intent is
persisted before external execution and carries an idempotency key, epoch, and
generation. Completion must match those bindings; old-epoch output is
quarantined and cannot mutate current authority.

Use these read and lifecycle surfaces:

```bash
PYTHONPATH=src python3 -m overseer.cli discover-agent-sessions --store state/overseer.sqlite3 --provider-id codex --instance-id overseer.default
PYTHONPATH=src python3 -m overseer.cli agent-session-status --store state/overseer.sqlite3 --instance-id overseer.default
PYTHONPATH=src python3 -m overseer.cli dispatch-agent-goal --store state/overseer.sqlite3 --instance-id overseer.default --prompt "continue" --idempotency-key request.example
PYTHONPATH=src python3 -m overseer.cli checkpoint-agent --store state/overseer.sqlite3 --instance-id overseer.default
PYTHONPATH=src python3 -m overseer.cli recover-agent --store state/overseer.sqlite3 --session-id session.example --initiated-by operator
```

The corresponding inspection API routes are `GET /agent-providers`,
`GET /agent-instances`, `GET /agent-sessions`, `GET /agent-dispatches`, and
`GET /agent-failover-executions`. Mutating routes are documented in
`docs/local-api.md`. Public responses use normalized identifiers and redacted
workspace references; they do not return raw prompts, transcripts, checkpoint
contents, credentials, or provider authentication output.

## Manual handoff

A manual handoff is an operator-selected replacement:

```bash
PYTHONPATH=src python3 -m overseer.cli handoff-agent --store state/overseer.sqlite3 --instance-id overseer.default --incoming-provider-id claude --initiated-by operator --approval-id approval.example
```

The exact approval subject is bound to the instance and incoming provider.
Overseer reserves and fences the instance, rejects new dispatch, drains or
cancels persisted in-flight work, verifies outgoing quiescence, captures a
checkpoint, validates incoming capabilities, persists the importing
transition, imports the handoff, and atomically promotes a new epoch.

Rollback cancels the incoming provider and resumes the outgoing provider only
after terminal cancellation is externally verified. Unsupported, failed,
timed-out, or ambiguous cancellation leaves the instance paused. Quarantining
a late result is evidence handling, not proof that an external action stopped.

## Controlled failover

The controlled failover workflow is not manual handoff. It selects the first
healthy provider in a previously approved fallback order, and only from
persisted evidence. Before evaluation, an authorized integration must persist
the policy, repeated health/transport observations, a fresh outgoing
checkpoint, active risk evidence, and verified provider readiness. Slow
response alone is not a health threshold.

Evaluate without executing:

```bash
PYTHONPATH=src python3 -m overseer.cli evaluate-agent-failover --store state/overseer.sqlite3 --instance-id overseer.default --policy-id policy.example
```

Blocked evaluations remain read-only. An allowed evaluation persists a
short-lived decision bound to the exact policy, evidence timestamps, checkpoint,
outgoing epoch, candidate, readiness references, and operation generation.
Execution requires that exact unconsumed decision and exact approval:

```bash
PYTHONPATH=src python3 -m overseer.cli failover-agent --store state/overseer.sqlite3 --instance-id overseer.default --decision-id decision.example --initiated-by operator --approval-id approval.example
```

Evidence is re-evaluated transactionally before reservation. Any changed epoch,
generation, policy, health, risk, readiness, checkpoint, expiry, or transition
blocks execution. Crash-ambiguous pre-import executions stay fenced and appear
in `GET /agent-failover-executions`; they require a separately approved,
externally verified recovery:

```bash
PYTHONPATH=src python3 -m overseer.cli recover-agent-failover --store state/overseer.sqlite3 --execution-id execution.example --initiated-by operator --approval-id approval.example
```

Recovery applies only to the exact persisted execution and fence binding.
Post-import ambiguity is not auto-recovered: reconcile the provider externally
under authorization, then use the matching lifecycle recovery path. Blocked or
ambiguous states remain paused; database cleanup never clears an uncertain
external side effect.

## Provider-native usage

Quark schedules work against provider-native usage evidence. Values are grouped
by provider, limit identifier, and native unit. Tokens, requests, credits, and
other incompatible units are never summed or converted. `svc.mcp.codex-usage`
is specifically the Codex usage observer, not a universal provider quota
service.

## Public-safe troubleshooting

Start with provider and instance status, then inspect normalized sessions,
dispatches, transitions, and failover executions. Report error categories,
record identifiers, readiness classifications, and timestamps. Do not paste
auth output, command output containing account data, prompt bodies,
transcripts, environment dumps, checkpoint evidence, or secret values.
