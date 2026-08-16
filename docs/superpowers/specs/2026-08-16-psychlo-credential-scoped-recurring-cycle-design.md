# Psychlo Credential-Scoped Recurring Cycle Design

## Status

Approved by the user on 2026-08-16. This document defines source and deployment behavior only. It does not itself authorize installing units, copying credentials, enabling a timer, or starting a service; those actions require an exact Overseer admin plan and authoritative approval.

## Objective

Allow Psychlo to continue bounded work on approved projects without manual accounting-feed intervention. Every recurring cycle must first create a fresh authority-signed Codex percentage observation and only then deliver it to Psychlo. A failed, stale, ambiguous, or unsigned observation must prevent delivery and scheduling.

## Existing State

- `overseer-psychlo-usage.timer` is installed but disabled.
- The timer currently targets the delivery-only `overseer-psychlo-usage.service`.
- `overseer-psychlo-meter.service` is static and guarded by an absent `producer-enabled` marker.
- The meter runs under `ProtectHome=tmpfs`, so it cannot use the normal Codex binary or login unless those inputs are exposed through a narrow approved boundary.
- The most recent observation is not refreshed automatically.

Enabling the existing timer unchanged would repeatedly consume stale input and would not satisfy the objective.

## Architecture

The implementation keeps signing and peer-delivery credentials in separate services.

```text
overseer-psychlo-cycle.timer
              |
              v
overseer-psychlo-cycle.service
       |                    |
       | start --wait       | start --wait only after success
       v                    v
overseer-psychlo-meter.service   overseer-psychlo-usage.service
       |                               |
       v                               v
fresh signed observation          authenticated Psychlo snapshot
```

### Meter service

`overseer-psychlo-meter.service` remains a one-shot producer and receives only the inputs required to read the provider window and sign an observation:

- the existing authority public configuration;
- the meter configuration selecting the exact Codex provider, limit, and window;
- the Ed25519 private signing key through `LoadCredential`;
- Codex `auth.json` through a separately named `LoadCredential` file;
- one exact, deployment-pinned Codex executable mounted read-only;
- the approved Overseer source and isolated Python runtime mounted read-only;
- write access only to the private Psychlo meter output directory.

The service sets `CODEX_HOME` to the systemd credential directory, where the credential is named `auth.json`. It does not bind `.codex`, the user's home directory, mutable Codex configuration, conversation history, or unrelated credentials. The exact Codex executable path and identity are frozen into the deployment plan. Executable drift blocks activation until a new reviewed plan is approved.

The existing `producer-enabled` marker remains a fail-closed activation gate. The deployment plan creates it as an owner-only regular file only after credential and executable preflight succeeds.

### Delivery service

`overseer-psychlo-usage.service` remains delivery-only. It receives the peer HMAC secret but never the authority private signing key or Codex login. It reads the newly published observation, validates the strict accounting contract, writes the private attribution ledger, and accepts success only after Psychlo returns a durable inserted or duplicate receipt.

### Cycle service

A new static `overseer-psychlo-cycle.service` owns sequencing but no credentials. It executes fixed commands only:

1. `systemctl --user start --wait overseer-psychlo-meter.service`
2. `systemctl --user start --wait overseer-psychlo-usage.service`

With `Type=oneshot`, systemd stops the command list on the first failure. Delivery cannot run if meter production fails. The cycle service cannot accept caller-controlled unit names or command arguments.

### Timer

The recurring timer is renamed or updated to target `overseer-psychlo-cycle.service`. It retains the existing bounded cadence and persistent catch-up behavior. The timer is installed disabled; enabling and starting it occurs only through the approved deployment plan.

## Scheduling and Safety Semantics

Each successful timer tick provides one fresh authenticated scheduling input. Psychlo remains the only scheduling authority. The cycle does not directly select projects, create rounds, bypass policy, or resume stopped projects.

Existing controls remain authoritative:

- strict percentage accounting and provider-reset binding;
- the configured safety reserve;
- global single-stream admission;
- exact project eligibility and priority;
- manual stop, blackout, failure throttle, and lifecycle gates;
- bounded policy exceptions with scope, expiry, and decision binding;
- exact A-Team project, plan, team, and lead identity;
- durable round callback and rollout delivery proof.

If no project is eligible, the fresh snapshot is still persisted but no round is created.

## Failure Behavior

- Missing or invalid Codex auth credential: meter fails; delivery does not run.
- Pinned Codex executable missing or changed: preflight or meter start fails closed.
- Provider schema, limit, window, reset, or percentage invalid: no observation is published.
- Signing key does not match the authority public key: no observation is published.
- Atomic publication fails: the prior observation remains intact; delivery does not run.
- Psychlo or Overseer unavailable: delivery remains failed or uncertain according to the existing durable outbox contract; no replacement payload is invented.
- Duplicate exact cycle: Psychlo returns a durable duplicate receipt and no duplicate round is created.
- Reboot catch-up: the persistent timer runs one bounded cycle; normal single-stream and idempotency rules prevent concurrent work.

No failure path broadens home-directory visibility, prints credentials, deletes durable records, synthesizes a result, or automatically weakens policy.

## Tests

### Unit and source-contract tests

- Meter unit uses `LoadCredential` for `auth.json` and the signing key.
- `CODEX_HOME` is the credential directory.
- Only the exact Codex executable is mounted; `.codex` and broad home paths are absent.
- Meter and delivery credentials remain separated.
- Cycle commands are fixed, ordered, and use `--wait`.
- Timer targets the cycle rather than delivery directly.
- Units remain disabled/static in source and contain no `[Install]` path that activates the meter or cycle independently.

### Failure tests

- Meter failure prevents the delivery command.
- Delivery failure makes the cycle fail.
- Missing marker, auth credential, signing credential, pinned executable, or observation directory fails closed.
- Stale observation cannot be mistaken for a successful current cycle.

### Integration tests

- Run the meter in a disposable systemd-compatible credential namespace and prove only the expected rate-limit read occurs.
- Verify a freshly signed observation is accepted by the existing attribution producer.
- Run one cycle against disposable loopback Psychlo and require a durable inserted receipt.
- Repeat the exact cycle and require duplicate receipt semantics with no duplicate round.
- Verify `systemd-analyze --user verify` for all units.

### Regression tests

- Existing manual meter and delivery commands continue to work independently.
- Existing v1.1 parsing and durable delivery recovery remain unchanged.
- Psychlo strict receiver, scheduling, quota, exception, and migration suites remain green.

## Deployment Plan

After source review passes, stage one exact Overseer admin plan that binds:

- reviewed source commit and tree digest;
- exact installed unit bytes and hashes;
- exact Codex executable path, version, and file digest;
- owner-only credential and marker paths without credential contents;
- timer cadence and target;
- pre-activation backup of installed units and timer state;
- one manual cycle canary before timer enablement;
- health, signed receipt, no-concurrency, and cleanup verification.

Execution order:

1. Back up current units and timer state.
2. Install reviewed meter, cycle, delivery, and timer units.
3. Create the owner-only activation marker.
4. Daemon-reload.
5. Run exactly one manual cycle and require a fresh observation plus durable receipt.
6. Confirm any dispatched round respects the single-stream and policy boundaries.
7. Enable and start only the recurring cycle timer.
8. Verify the next trigger and leave all services healthy.

## Rollback

Rollback disables and stops the recurring timer first, restores the captured unit files and prior timer state, removes only the plan-owned activation marker, daemon-reloads, and verifies that no recurring trigger remains. It preserves observations, attribution ledgers, policy revisions, projects, rounds, results, estimates, and audit history. Credentials and runtime directories are not deleted automatically.

## Acceptance Criteria

- A timer tick cannot deliver without a newly successful signed meter run.
- The meter receives only scoped credentials and the exact pinned Codex executable.
- The delivery service never receives Codex auth or the signing key.
- No broad home or `.codex` bind is introduced.
- One manual canary proves fresh observation, strict delivery, and durable receipt before timer enablement.
- Recurring activation is represented by an exact approved Overseer admin plan.
- Rollback disables recurrence without destroying durable project or accounting state.
