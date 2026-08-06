# Reusable Approval Facility SDD Progress

Baseline: Overseer `a42e3d5`, Roadex `31ead2c`, DonutHole `4739ea7`.
Baseline qualification: Overseer focused approval tests passed. Roadex timeout-only failures passed on serial rerun. DonutHole fixture-backend timed out once at the default harness limit and passed on immediate extended-timeout rerun.

## Task status

- Task 0 — approval-source conformance contract: complete and release-reviewed.
  - Overseer head: `cf57cae6b1a8a39e524700717be874f716da24ca`
  - Roadex head: `40771faf43d25c11ae5f0413bc640044da44f468`
  - DonutHole head: `da6155e7f4a38f9d4865226b7b0b6dac3fefbb53`
  - Canonical fixture SHA-256: `4d79ef227927c13984ca2f913017352576d3ab8721063197ae049f4f57cf12e7`
  - Final review: PASS; no blocking findings.
- Task 2 — allowlisted approval-source adapter registry: complete and
  release-reviewed at `3e346baa9425678a07b38c3db29d56896bed1472`.
  - Final review: PASS; no blocking findings.
- Capability A — contract and acceptance harness: complete.
  - Task 1 complete and release-reviewed at
    `494b4acd0eae9772260971a5b3639d7b74831cec`.
  - Task 2 complete and release-reviewed:
    - Overseer canonical head: `bf2547391adab5d18985f8a49b46610957c69a8a`
    - TheUnderdark mirror head: `5983ac4e00e09d897080059bbe0cec1464017c44`
    - Fixture SHA-256: `e6bb6318fc9f65cfe96d7e648a5c39573b0482373d9b2413deeb0eb94ce3b095`
    - Planned runtime identity: `sha256:b44d2602de7e404e5b1731beb4c40272ffcbde16f47e2ccb6250c15c4e287e8b`
  - Task 3 complete and release-reviewed at
    `f474839327a8fd6c067b25cc6fae04e201f6639f`.
  - Task 4 complete and release-reviewed:
    - TheUnderdark head: `839e3ccf274c9e296ad9d5fb8b7c8348073e8ea4`
    - Overseer head: `dea8e1ebfa709c8f5747df9f8716fe549ac4394b`
  - Task 5 complete and release-reviewed:
    - TheUnderdark head: `dd6923c490a17513452f3c58e1d4bcf89baa3867`
    - Overseer head: `f7845712d546f3d1ffb3394e5b6d93e9dc92fb09`
  - Capability A complete and release-reviewed:
    - Overseer head: `eddbe0658c289b00fb5e311966e6d78258063755`
    - TheUnderdark head: `1fc8c86f67cd3ee7125e33d915de7fd34817ab06`
    - Fixture SHA-256: `ff0c2354b2099721308c539a286198af027c0d890ede8dc400cc42eb06484305`
  - Known downstream boundary: Capability B must prospectively rebind the
    exact human-plan source evidence/scope digests; no Capability A backfill.
- Capability B Task 1 — typed intent, report, outbox, and bundle contracts:
  complete and release-reviewed at
  `85bba61398a89f4af20af7f91b9721ccbdaa80ff`.
  - Final review: PASS; no blocking or minor findings.
  - Focused Task 1 tests: 23 passed.
  - Related contract selection: 72 passed, 5 documented skips.
- Capability B Task 2 — authoritative rebuild and deterministic preflight:
  complete and release-reviewed at
  `ebbe5be3184bf3332db9c86e8ae5905a7a5d2acc`.
  - Final review: PASS; no Critical, Important, or material Minor findings.
  - Exact owned scope: `src/overseer/provisioning_bundle.py` and
    `tests/test_provisioning_bundle.py`.
  - No deployment, restart, approval action, or provisioning execution was
    performed.
- Capability B Task 3 — schema v3, atomic source/binding/bundle persistence,
  and production evidence hardening: complete and release-reviewed at
  `e9e5b0966c52c6f52b18f67ba5098c26ecb43e0b`.
  - Final review: APPROVE; no Critical or Important findings.
  - Focused four-finding regression: 11 passed.
  - Full provisioning suite: 166 passed.
  - Full touched suite: 700 passed, 1 documented unrelated test deselected.
  - Configured TheUnderdark cross-repository acceptance: 10 passed.
  - Non-blocking review note: cleanup fails closed and closes stdout but does
    not escalate from `terminate()` to `kill()` after a bounded wait failure.
- Capability B Task 4 — public preflight, authoritative stage, and status API
  and CLI: complete and release-reviewed at
  `ecdd2b1af79533a258222230a63be2c1e9b7640c`.
  - Final review: APPROVE; no Critical, Important, or Minor findings.
  - Full touched suite: 786 passed, 1 documented deselection.
  - Configured TheUnderdark cross-repository acceptance: 10 passed.
  - Persistent wrapper-close failure independently closes the raw SQLite
    connection; the real descriptor-leak reproduction showed zero growth.
- Capability B Task 5 — atomic review-outbox materialization and exact dispatch:
  complete and release-reviewed at
  `34e53524d1261d4e9e18026f9e0c1ec73582997e`, with documentation cleanup at
  `9e01096530e09f71bcdbc0a4cccf02d6e5e3ae8b`.
  - Final review: APPROVE; no Critical or Important findings.
  - Required selector: 49 passed; full affected tests: 307 passed.
  - Core regression: 381 passed; configured disposable acceptance: 10 passed.
  - Exact automatic terminal outcomes are approved or correction requested;
    human rejection remains a separate authoritative decision path.
- Capability B Task 6 — approval gate, legacy compatibility, and capability
  verification: complete and release-reviewed at
  `be04836103defa4cceae5023ecc5da6d69a9bdbf`.
  - Final security review: APPROVE; no Critical or Important findings.
  - Case-normalized independent-human validation covers approve, deny, and
    revision; root/chain freshness and projection redaction remain closed.
- Delta Task 7 — separate protected-app publication workflow plan: complete
  and release-reviewed at
  `e5f3fa0051a257936ac6cc72fd97d79de927a50e`.
  - Final review: PASS; no Critical, Important, or Minor findings.
  - Publication remains default-off and preserves separate exact approvals;
    no gateway, firewall/IDS, deployment, or activation authority was added.
- Delta Task 3 — Roadex typed consumer: complete and release-reviewed.
  - Roadex head: `6c5b27e6284d07f56f9062e88881ad63eab22418`.
  - Owner producer inherited-FD source:
    `3709904793f3bc8e780d593ba5e45687ebedf8e7` at owner head
    `50ba53c10510b3678fa4247b119b9b6ee31e0789`.
  - Final Terra and Sol reviews: APPROVE.
- Delta Task 4 — DonutHole typed consumer: complete and release-reviewed.
  - DonutHole consumer head: `c2b7b63f01aab0f9621da273ae9e89ce32e4a176`.
  - Latest cleanup-precedence source:
    `cfcc2a78c2b57fc25b5a44049b3706417d1aea72`.
  - Owner producer inherited-FD source:
    `3709904793f3bc8e780d593ba5e45687ebedf8e7` at owner head
    `50ba53c10510b3678fa4247b119b9b6ee31e0789`.
  - Final Sol review: APPROVE; no Critical, Important, or Minor findings.
  - Verification: consumer unittest 56, pytest 58, and npm 28; format, lint,
    typecheck, and build passed; producer bundle tests passed 298.
  - Fixture SHA-256 values matched: intent
    `871e12893073020d1e072ca38185b153d92930ac525f2fa6a387a25877a76785`;
    approval source
    `4d79ef227927c13984ca2f913017352576d3ab8721063197ae049f4f57cf12e7`.
  - No live actions were performed.

No deployment, restart, protected-host mutation, publication, approval action,
or provisioning execution is authorized by this source milestone.

- Capability C Task 1/C1 — durable execution contracts: complete and
  release-reviewed at `872470b4a890ed275d6247dd820e1da736d29bba`.
  - Focused execution tests: 38 passed.
  - Combined compatibility tests: 476 passed.
  - Both Terra reviews: APPROVED.
  - Final Sol security review: APPROVED; no findings.
  - No live actions were performed.
- Capability C Task 2 — resumable phase coordinator: complete and
  release-reviewed at `cf559e682e220c94d10f0c766b2c9a8410f6f4ea`.
  - Independent exact five-file suite: 212 passed in 326.37s.
  - Terra contract review APPROVE: 15 selected tests.
  - Terra policy review APPROVE: 20 focused tests plus 3 additional
    concurrency/completion tests.
  - Final Sol security review APPROVE; no Critical, Important, or Minor
    findings.
  - Sol exact suite: 212 passed in 318.43s; focused trigger/readback probes:
    5 passed in 15.18s.
  - INSERT/UPDATE/DELETE trigger tamper, exact readback, v6 migration
    atomicity, epoch fencing, process-liveness/scoping, orphan recovery,
    authority revalidation, and transaction-exit cleanup were verified
    fail-closed.
  - No live actions were performed.
- Capability C Task 3 — structured, convergent, evidence-bearing host
  operations: complete and release-reviewed at
  `e613f2f2413ae70e590a15091f2775d815a49f35`.
  - Production hardening commits:
    - `8293254b5bca30d87b387aa5605483018d220914` — real adapter evidence,
      virtualenv-safe cleanup, physical/logical runtime-reference checks,
      bounded fail-closed proc parsing, child-symlink race handling, and
      descendant device-boundary enforcement.
    - `e613f2f2413ae70e590a15091f2775d815a49f35` — finite streaming runtime
      reference scans capped at 1,024 processes and 512 descriptors per
      process, with limit-plus-one failure and ignored/non-numeric accounting.
  - Focused host-operation suite: 118 passed with warnings as errors.
  - Full affected five-file suite: 349 passed with warnings as errors.
  - Both Terra reviews: APPROVED.
  - Final Sol security review: APPROVED; no P0 or P1 findings.
  - Root-visible `/proc` smoke returned a clear, zero-reference result for an
    unrelated runtime path.
  - No live actions were performed.
- Capability C Task 4 — TheUnderdark active runtime attestation: complete and
  release-reviewed at `98d02c193e8fa00bf232b0f7adcfeb41e2e1e107`.
  - Immutable range SHA-256:
    `94ed198c608522620dc192c8ab2847aa0715d6c503469dad17b0b9ec455b5a92`.
  - Warning-strict focused suite: 67 passed.
  - Warning-strict full TheUnderdark suite: 247 passed, 1 documented skip.
  - Capability A owner/consumer runtime-digest parity: verified equal.
  - Contract and Terra security reviews: APPROVED.
  - Final Sol security review: APPROVED; no P0 or P1 findings.
  - Task 5 integration must run the package from the attested
    `/opt/theunderdark/src/theunderdark` tree, normalize the complete deployment
    root as root-owned and non-group/world-writable, validate it before
    promotion and on verified no-op, and bind the exact runtime root, source
    commit, runtime digest, and configuration digest into `ExecStart`.
  - No live actions were performed.
  - Task 5 — Overseer attestation and behavior acceptance — is next.
