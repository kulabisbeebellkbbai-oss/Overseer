# Maintenance And Patch Operations

O'Brien owns scheduled maintenance, installs, updates, patch deployment, restart windows, rollback readiness, and post-change verification.

## Intent

Maintenance work must not surprise active project threads or consume a shared service while another role has it checked out. Overseer should make every install, patch, upgrade, restart, or cleanup operation visible as a planned operation with a window, affected resources, interruption risk, rollback plan, and verification evidence.

## Operation Flow

1. Identify the target resource and dependency set.
2. Classify the operation as install, update, patch, restart, backup, cleanup, migration, audit, or repair.
3. Reserve a maintenance window through the normal claim/deconfliction model.
4. Require a rollback plan for medium, high, or critical risk work.
5. Block the operation if active exclusive claims conflict with the resource, dependencies, ports, physical assets, or exclusive groups.
6. Run pre-change checks and record the baseline state.
7. Execute only the approved operation scope.
8. Capture post-change verification from Julian, Odo, Dax, Kira, or Quark as needed.
9. Release the maintenance claim only after verification passes or rollback evidence is recorded.

## Required Evidence

- planned start and end time
- target resource ids and affected dependency ids
- operation kind and requested version or state
- interruption policy
- pre-change check summary
- rollback plan for non-low-risk work
- post-change verification evidence ids
- final result: completed, rolled back, blocked, or failed

## Gates

- High-risk or critical maintenance requires Sisko approval.
- Security-sensitive maintenance also requires Odo review and human approval before live protective or firewall-affecting changes.
- Work that affects physical devices, power, or storage requires Kira identity and risk confirmation.
- Work that affects a quota-limited service must ask Quark for a window that will not waste limited capacity.
- Work cannot close until Julian's health evidence confirms recovery or the failure is explicitly recorded.

## Maintenance Summary

O'Brien's compact operator read model is available with:

```bash
PYTHONPATH=src python3 -m overseer.cli maintenance-summary --store state/overseer.sqlite3
PYTHONPATH=src python3 -m overseer.cli inspect-packages
PYTHONPATH=src python3 -m overseer.cli plan-package-updates --store state/overseer.sqlite3
```

It summarizes persisted maintenance targets plus install, package index refresh, package upgrade, and restart admin plans, approval state, rollback and verification step coverage, execution status, and risk distribution.

`inspect-packages` is read-only. It runs `apt list --upgradable`, parses package names, candidate versions, installed versions, repository labels, and architectures, and does not run `apt-get update`, install packages, upgrade packages, remove packages, or use sudo.

`plan-package-updates` uses the same read-only inspection result to stage O'Brien-owned admin plans for package metadata refresh and package upgrades. It writes only Overseer plan records; the normal approval, policy, rollback, and execution gates still decide whether package commands may run.

Advisory feed integration is available through the Admin page and local API:

```bash
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8766/maintenance/advisories
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"packages":["openssl","openssh"],"source":"nvd","max_results_per_package":5}' \
  http://127.0.0.1:8766/maintenance/advisories/refresh
```

Dashboard loads read only the local advisory cache. Refresh requests are
explicit actions and write only `state/advisory-cache/` records, not host package
state. The supported feed sources are NVD CVE API 2.0 for general CVE keyword
matching and Debian Security Tracker JSON for Debian package impact. Review
Advisory Findings before approving package update plans.

`apt_install` and `apt_upgrade` plans are for Debian apt package names only.
Provider-prefixed identifiers such as `npm:...`, `flatpak:...`, `pip:...`,
`pipx:...`, or `snap:...` are blocked before execution. Use
`npm_global_install` or `flatpak_install` for those supported providers so
O'Brien can apply the correct command, rollback, and verification contract.
