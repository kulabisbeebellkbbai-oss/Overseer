# Approval-source contract v1 manifest

## Canonical fixture

- Path: `tests/fixtures/approval_source_contract_v1.json`
- SHA-256: `4d79ef227927c13984ca2f913017352576d3ab8721063197ae049f4f57cf12e7`
- Purpose: Freeze the safe, source-neutral approval locator and status-projection
  conformance data used by Overseer, Roadex, and DonutHole before any adapter,
  staging, API, service, deployment, or live-state work begins.

## Exact fixture mirrors

Each repository records the same canonical JSON bytes at its listed path.

| Repository | Fixture path | SHA-256 |
| --- | --- | --- |
| Overseer | `tests/fixtures/approval_source_contract_v1.json` | `4d79ef227927c13984ca2f913017352576d3ab8721063197ae049f4f57cf12e7` |
| Roadex | `tests/fixtures/approval_source_contract_v1.json` | `4d79ef227927c13984ca2f913017352576d3ab8721063197ae049f4f57cf12e7` |
| DonutHole | `tests/fixtures/approval_source_contract_v1.json` | `4d79ef227927c13984ca2f913017352576d3ab8721063197ae049f4f57cf12e7` |

## Source heads reviewed for this contract task

| Repository | Worktree | Source head |
| --- | --- | --- |
| Overseer | `Overseer/.worktrees/reusable-approval-facility` | `a42e3d5b2507e0f1e33bfe91d015e60e4dc58692` |
| Roadex | `Roadex/.worktrees/reusable-approval-facility` | `31ead2cb16d0e81ad163585655d50e66b273bace` |
| DonutHole | `Overseer/.worktrees/donuthole-reusable-approval-facility` | `4739ea7946ab177b7e36d8b86df524b78d329153` |

This manifest reviews fixture data only. It does not approve implementation,
deployment, activation, service restart, protected-host mutation, publication,
or provisioning.
