# Admin Change Plans

Admin change plans are Overseer's bridge from observed host evidence to real IT actions. A plan is not execution. It is the approval artifact that must exist before package installs, package index refreshes, package upgrades, service restarts, firewall changes, network exposure, or active blocking actions.

## Included Fields

- Current state.
- Proposed new state.
- Exact command steps.
- Reason for each step.
- Risks and expected impact.
- Rollback commands.
- Verification commands.
- Required approval level.

## Supported Plan Types

- `user_service_restart`
- `apt_install`
- `apt_update`
- `apt_upgrade`
- `flatpak_install`
- `npm_global_install`
- `python_hashed_venv_provision`
- `firewall_allow_tcp`
- `firewall_deny_tcp`
- `block_ip`

## CLI

```bash
PYTHONPATH=src python3 -m overseer.cli plan-admin-change --store state/overseer.sqlite3 --plan-id admin.restart.overseer-api --kind user_service_restart --target overseer-api.service --reason "reload approved code" --current-state active
PYTHONPATH=src python3 -m overseer.cli plan-admin-change --store state/overseer.sqlite3 --plan-id admin.install.nmap --kind apt_install --target nmap --reason "enable approved local audit"
PYTHONPATH=src python3 -m overseer.cli plan-admin-change --store state/overseer.sqlite3 --plan-id admin.apt.update --kind apt_update --target apt --reason "refresh package metadata"
PYTHONPATH=src python3 -m overseer.cli plan-admin-change --store state/overseer.sqlite3 --plan-id admin.apt.upgrade.sqlite --kind apt_upgrade --target sqlite3 --package sqlite3 --reason "apply approved patch"
PYTHONPATH=src python3 -m overseer.cli plan-admin-change --store state/overseer.sqlite3 --plan-id admin.flatpak.obsidian --kind flatpak_install --target md.obsidian.Obsidian --reason "install approved local documentation editor"
PYTHONPATH=src python3 -m overseer.cli plan-admin-change --store state/overseer.sqlite3 --plan-id admin.npm.obsidian-mcp --kind npm_global_install --target obsidian-mcp-server --reason "install approved Documents MCP bridge"
PYTHONPATH=src python3 -m overseer.cli plan-admin-change --store state/overseer.sqlite3 --plan-id admin.firewall.8443 --kind firewall_allow_tcp --target tcp/8443 --port 8443 --reason "publish approved local service"
PYTHONPATH=src python3 -m overseer.cli authorizations-required --store state/overseer.sqlite3
PYTHONPATH=src python3 -m overseer.cli approve-admin-change --store state/overseer.sqlite3 --plan-id admin.restart.overseer-api --approved-by sisko
PYTHONPATH=src python3 -m overseer.cli cancel-admin-change --store state/overseer.sqlite3 --plan-id admin.block.example --canceled-by odo --reason "reserved documentation address; no observed hostile traffic"
PYTHONPATH=src python3 -m overseer.cli execute-admin-change --store state/overseer.sqlite3 --plan-id admin.restart.overseer-api
PYTHONPATH=src python3 -m overseer.cli admin-executions --store state/overseer.sqlite3
PYTHONPATH=src python3 -m overseer.cli admin-summary --store state/overseer.sqlite3
```

## Boundary

The planner never runs live commands. It produces the exact change list required by the approval gate. The live admin adapter layer must verify `approved=true`, execute only the approved steps, record evidence, and preserve rollback status.

Recording approval does not execute the plan. It only updates the stored approval metadata so the execution adapter can see that a specific command list was approved.

Live admin execution is now described by an explicit adapter capability table. Approved user-service restart plans are enabled by default. Package install, package index refresh, package upgrade, firewall allow/deny, and source-block adapters remain disabled unless the same store contains an approved adapter enablement request for that exact kind. The readiness view reports each plan's `adapter_status` so disabled live actions cannot be confused with ready Overseer execution. Use `admin-adapter-enablement-plan` or `GET /admin/adapter-enablement-plan` to generate the required read-only approval plan before any disabled adapter is enabled.

Adapter enablement requests persist the human approval record for that work. Approval changes only the effective adapter capability for that store and kind; it does not approve any specific host change, modify the host, or run commands. Each admin plan must still pass its own approval, IDS review when applicable, command-boundary validation, execution recording, and verification.

Canceling a plan keeps the record visible but removes it from the pending authorization queue and prevents execution. Use cancellation for placeholders, superseded plans, or plans created from disproven evidence.

Live execution support is controlled by the effective adapter table. User-service restart is enabled by default; package install, package index refresh, package upgrade, firewall allow/deny, and source-block execution require approved adapter enablement for the store plus the specific admin plan approval and any IDS review gate.

Approved apt-family execution uses a noninteractive apt/debconf environment with standard input closed. This keeps package operations from opening terminal dialogs after the command list has already been approved. Package defaults still apply unless the approved plan explicitly includes a different package configuration step.

Apt-family plans accept apt package names only. Overseer rejects
provider-prefixed install targets such as `npm:obsidian-mcp-server` or
`flatpak:md.obsidian.Obsidian` before execution. Use `npm_global_install` and
`flatpak_install` instead so those software sources get their own command,
rollback, and verification steps.

Execution results are persisted and can be reviewed with `admin-executions` or the loopback API. Blocked execution attempts are also persisted so O'Brien and Sisko can see why a plan did not run.

Every execution attempt also writes an audit event keyed to the admin plan. Completed executions use `executed`; blocked or failed attempts use `blocked` and cite the execution result id as evidence.

`admin-summary` is the compact operator view for O'Brien and Sisko. It reports plan counts, pending authorizations, executable plans, execution counts by status, pending plan details, and recent admin audit events.

For firewall-affecting plans, `authorizations-required` and `admin-summary` also report the IDS/firewall review gate. The queue distinguishes missing packages, prepared packages that need prompt export, exported prompts that need submission, submitted packages waiting for advisory results, revision-required packages, and accepted advisory results that are ready for human approval.

IDS/firewall review package lifecycle changes also write audit events keyed to the package id. Preparing and submitting a package use `requested`, prompt export uses `verified`, accepted results use `approved`, and revision-required results use `rejected`.
# Hash-pinned Python virtual environments

`python_hashed_venv_provision` is a disabled-by-default O'Brien adapter for
creating a new, final versioned virtual environment outside a repository. A
plan must carry a typed manifest containing the source commit/tree or
`pyproject.toml` digest, the immutable requirements-lock digest, resolver
provenance, and every resolver/runtime artifact URL, version, and SHA256.

The adapter is insert-only: it rejects repository-local targets, symlinked
path components, existing destinations, unsafe ownership/modes, VCS/editable
requirements, ranges, duplicate packages, and package-manager configuration
flags. When a wheelhouse is supplied it uses a fixed local wheelhouse with
`--require-hashes --no-deps --only-binary=:all: --no-index`; it always keeps
`PIP_CONFIG_FILE=/dev/null` and does not modify system Python. Verification
imports the expected package and checks its version. Creation, installation,
and verification run with a cleared fixed environment (`PATH`, `PYTHONPATH`,
`PYTHONHOME`, `PIP_*`, and `UV_*` protections); Git verification, when used,
also requires an absolute hash-pinned Git executable. Immediately before
creation, the adapter seals the exact lock and wheel bytes into an owner-only
manifest-bound staging area, and the install commands consume only those
sealed paths.

Execution requires both the exact human approval for the stored plan and a
separate approval to enable the `python_hashed_venv_provision` adapter. A
preflight step atomically claims the final 0700 target with the full plan
digest before the external venv tool runs; replay accepts only that marker and
the matching sealed-input marker. Rollback refuses to touch any path without
the exact plan digest marker. Canonical execution also binds
the plan id, immutable header, commands, rollback, verification, risks, and
manifest, so approval/risk downgrades or command edits fail closed. Service
activation is outside this adapter and requires its own separately approved
plan.
