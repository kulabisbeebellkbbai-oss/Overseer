# Overseer v1.1 Release Verification

## Recommendation

**SOURCE/PACKAGE READY. LIVE ACTIVATION NOT AUTHORIZED.**

Overseer `1.1.0` now provides an always-running, independently scheduled,
bounded collection runtime whose API and UI read durable state instead of
launching collection work inline. Failures create durable triage evidence and
advance only through bounded repair and approval gates.

## Release identities

- Branch: `feature/overseer-v1-1-autonomous-operations`
- Reviewed source commit: `2485a11763b0ab15c77dff8025ae2467a09d0ca0`
- Reviewed source tree: `78adfc7056821afda626fb6a7b6e3595ebda9ed2`
- Version: `1.1.0`
- Wheel: `artifacts/release/overseer_local-1.1.0-py3-none-any.whl`
- Wheel SHA-256:
  `616449372558b0eec749a73044fcdf549c558c2bfcbfe23e4c4974d4c8fa2887`

The wheel has valid compressed data and RECORD entries, embeds matching 1.1.0
metadata, includes the new deadline and maintenance projection modules, and
does not package the test tree.

## Delivered v1.1 behavior

- Durable scheduler with independent intervals, jitter, timeouts, leases,
  bounded global/key concurrency, coalesced requests, backoff, circuits,
  incidents, and repair decisions
- Scheduled durable Git, storage-capacity, firmware/preflight, host, package,
  health, discovery, freshness, and authorized action-family jobs
- Projection-only dashboard/API reads for operations, service, package,
  firmware, software, storage, backup, virtual, and Git evidence
- Queue-only UI/API refresh controls that cannot fan out inline host work
- Absolute worker/store deadlines, remaining-budget SQLite locks, no-create
  verified database opens, post-expiry rollback, and correct timeout outcome
- Killable firmware collection, bounded EFI traversal, and atomic paired
  firmware projection updates
- Bounded host command sequence with shared whole-job deadline
- Separate runtime/API systemd templates and exact canary, activation,
  provenance, migration, verification, and rollback procedure
- Responsive dashboard verified at mobile, tablet, and desktop sizes, including
  automatic/manual modes, no horizontal overflow, persistent mode selection,
  and 44-pixel action targets

## Test and artifact evidence

Final exact-head no-cache run:

```text
2232 passed, 31 skipped in 444.02s
```

Canonical harness status: `passed`.

- Artifact: `artifacts/regression/overseer-v1.1-final.json`
- SHA-256:
  `2151523b777323a749be738a635106d60b75fa5b201b34733f1d306c7a14c507`
- provider-neutral-agent: 304 passed, 1 deselected
- operator-functional: 115 passed
- operator-performance: 7 passed
- project-regression: 2232 passed, 31 skipped

The first full run after deadline enforcement exposed one deterministic host
inspection timeout. The exact test failed again alone, proving a real defect.
After the host whole-job budget fix, the exact test, a 93-test related gate,
the complete no-cache suite, and the canonical serial harness all passed.

Disposable Playwright acceptance covered 390x844, 820x1180, and 1440x1000
viewports. Automatic and forced desktop/tablet/mobile modes had no horizontal
overflow; mode persistence survived reload; queue and mode controls measured
44 pixels; console output was clean after complete fixtures. The disposable
server/browser were stopped and removed.

## Security and independent review

The final Daybreak review is **APPROVED** for the exact source commit, tree,
and wheel above. It reproduced both prior blockers as fixed and found no
remaining release blocker. Independent Terra reviews separately approved the
deadline/SQLite TOCTOU, systemd path, firmware persistence, and host collection
corrections.

## Integration preservation

- Existing Psychlo and Quark timer ownership is preserved; Overseer projects
  their freshness rather than replacing their schedules.
- Existing Protected Gateway prefix/authentication, Roadex authority, Codex
  delivery identity, claim/approval, IDS, audit, and external-project
  boundaries remain covered by compatibility/security tests.
- No other project checkout was changed.
- The original `main` checkout remains at `c51fed8` with its pre-existing
  modified/untracked work preserved.

## Live state and activation boundary

Read-only observation shows `overseer.service` and `overseer-api.service` are
active and the loopback API health endpoint responds successfully. The runtime
service still uses the legacy flag-driven `ExecStart`; it is not this reviewed
v1.1 candidate.

Activation requires a separately approved, fully resolved plan following
`docs/v1.1-operations.md`: clean deployment source, exact commit/tree and
manifest, interpreter/dependency/environment/unit hashes, WAL-consistent
backup and canary, approval evidence, maintenance window, post-start checks,
and exact rollback condition. No live service, store, gateway, firewall, or
external project was changed during this release-preparation work.
