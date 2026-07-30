# Provider Adapter Contract

Provider adapters translate a verified interface into the normalized
`PrimaryDriver` contract. They do not implement policy, approvals, scheduling,
or database access.

## Implementation checklist

1. Add one focused module under `src/overseer/agent_adapters/`.
2. Declare only capabilities proven by the selected transport.
3. Verify executable discovery against the configured allowlist.
4. Construct subprocess commands as argument arrays with `shell=False`.
5. Confine execution to the selected workspace and use bounded time, stdout,
   stderr, and event parsing.
6. Prove external session identity and bind every result to the request,
   internal session, external session, provider, and driver epoch.
7. Normalize terminal success, rejection, timeout, authentication, protocol,
   and cancellation states without returning raw provider output.
8. Implement checkpoint, cancellation, discovery, resume, and handoff import
   only when the provider interface proves them.
9. Return `unsupported_capability` for unsupported operations. Never scrape a
   UI or weakly emulate continuity.
10. Add fake-executable contract tests for argument shape, cwd confinement,
    identity spoofing, malformed output, size bounds, timeouts, and redaction.

Adapters must never interpolate a prompt, workspace, identifier, or credential
into a shell command. Input belongs on a bounded stdin or a provider's verified
argument boundary. Logs and normalized evidence may contain stable identifiers,
hashes, state, timing, and error category; they must exclude prompts,
transcripts, credential values, cookies, environment dumps, checkpoint content,
and raw authentication output.

## Lifecycle semantics

`discover` and `resolve` must not invent sessions. `start`, `resume`,
`dispatch`, `inspect`, `checkpoint`, `cancel`, `recover`, and `import_handoff`
must return normalized records with exact identity bindings. An acknowledgement
or running event is nonterminal. Ambiguous output is a protocol error, not
success. A stale completion is quarantined by the manager.

Handoff import accepts only a normalized, redacted package. The adapter must
acknowledge the incoming provider, session, epoch, and handoff identities before
promotion. Cancellation must identify the exact external session; an
unsupported or unverifiable cancellation cannot authorize rollback.

## Verification levels

Ordinary tests use deterministic fake executables and never contact a live
provider. Claude is proven by fake-executable, manager handoff, identity,
protocol, and bounded-output tests. A live Claude prompt was not run because
explicit opt-in was absent, so it is not live-proven.

Live tests use the `live_agent` marker and require an explicit provider opt-in,
valid local authentication, and a disposable workspace. They are excluded from
ordinary regression. Qwen Code, Mistral Vibe, and Antigravity remain
live-unavailable until their local programmatic interfaces are verified; do
not invent commands for them.
