# Overseer v1.1 Final Defensive Security Re-review

## Verdict

**APPROVED** for source/package release at exact reviewed source commit
`2485a11763b0ab15c77dff8025ae2467a09d0ca0`, tree
`78adfc7056821afda626fb6a7b6e3595ebda9ed2`, and wheel SHA-256
`616449372558b0eec749a73044fcdf549c558c2bfcbfe23e4c4974d4c8fa2887`.

No release-blocking security or correctness finding remains. This approval
does not authorize installation, live-store migration, service changes,
gateway/firewall changes, or changes to any external project.

## Reviewed scope

- Complete v1.1 range: `08bafba..2485a11`
- Corrective range after the blocked candidate: `8faf5e8..2485a11`
- Always-running scheduler, queue-only controls, durable projections,
  incidents/repair gates, HTTP bounds, systemd templates, activation/rollback
  procedure, package contents, and external integration boundaries
- Repository-local tests, disposable SQLite stores, disposable loopback HTTP,
  and disposable systemd unit verification only

## Remediation verification

| Finding | Status | Evidence |
| --- | --- | --- |
| Post-deadline projection persistence | Resolved | Scheduler deadlines propagate through a worker-local context into SQLite. Collection connections use remaining-budget lock timeouts, open an existing no-follow/no-create database descriptor, refuse missing/unmigrated/non-WAL stores, check expiry before transactions and commit, and map deadline exceptions to `TIMED_OUT`. Locked regressions cover health, host, package, and storage persistence. The original storage-lock reproduction now records `timed_out` with no projection afterward. |
| Space-containing systemd paths | Resolved | API environment and command arguments are quoted. Runtime and API units render successfully from paths containing spaces, `systemd-analyze verify` returns zero with empty stderr, and both canary and activation procedures fail on verifier stderr. |
| Host inspection exceeded its whole-job budget | Resolved | The seeded timeout is five seconds, each command receives only the remaining absolute budget, no later command starts after expiry, and scheduled collection retains the previous non-firewall command profile. |

## Preserved controls

- API request bodies, reads, handlers, and host work remain bounded.
- API binding remains loopback-only; collection controls require admin
  authorization through root and Protected Gateway prefix routes.
- Dashboard GETs read durable projections and do not launch host commands or
  DNS requests.
- Pending collection requests coalesce transactionally.
- Unsafe action families remain disabled until durably authorized.
- Repair execution remains incident-, binding-, risk-, approval-, and
  idempotency-gated; service repair stages approval rather than restarting
  inline.
- Firmware collection remains killable and deadline-bound, with atomic paired
  projection persistence.
- Existing Psychlo, Quark, Roadex, Protected Gateway, Codex delivery, IDS, and
  external-project authority boundaries remain covered by compatibility tests.
- No external-project mutation path was enabled or used.

## Verification evidence

- Exact no-cache project run: `2232 passed, 31 skipped in 444.02s`.
- Canonical harness: passed; SHA-256
  `2151523b777323a749be738a635106d60b75fa5b201b34733f1d306c7a14c507`.
  - provider-neutral-agent: 304 passed, 1 deselected
  - operator-functional: 115 passed
  - operator-performance: 7 passed
  - project-regression: 2232 passed, 31 skipped
- Daybreak focused re-review: 99 passed plus 131 passed.
- Wheel RECORD, metadata, source-byte comparison, sensitive-entry checks, and
  source/package identity checks passed.
- Both review ranges passed `git diff --check`; the reviewed tracked worktree
  stayed clean.

## Residual operational conditions

1. Python worker threads are not forcibly terminated. A timed-out worker keeps
   its lease until exit, preventing overlap, while SQLite persistence is
   deadline-protected.
2. The harness JSON is bound by its verified hash and external source record;
   it does not embed commit/tree identity internally.
3. The artifact-bearing development worktree contains ignored build/test
   outputs and is not an activation source. Use a clean deployment tree.
4. Before activation, verify the approval record's approved status and exact
   source, unit, environment, store, window, and rollback bindings—not only
   that its identifier appears in evidence.
5. Keep the API loopback-only, use one managed runtime, keep action callbacks
   idempotent and side-effect fenced, and never place secrets in request reason
   fields.

## Authorization boundary

**Approved:** source/package release for the exact commit, tree, and wheel
listed above.

**Not approved:** merge/push, live installation or migration, service
start/stop/restart/enablement, gateway/firewall/IDS changes, or mutation of any
external project. Those remain separate exact-plan approval gates.
