# Security Monitoring

Odo owns security posture, intrusion signals, audit findings, and protective-action coordination.

## Intent

Overseer should treat security as an evidence-backed workflow, not as an automatic permission to change the host. The first slice records observations and recommends a protective posture. Any live firewall, routing, privilege, remote-access, quarantine, or destructive action remains behind explicit approval and the relevant project safety gates.

## Observation Flow

1. Capture the signal source, affected resource, severity, confidence, and observed indicator.
2. Classify whether the signal is informational, suspicious, intrusion-likely, confirmed incident, policy violation, or vulnerability.
3. Determine the response posture: monitor, audit, isolate, quarantine, rotate credential, block traffic, stop service, patch, restore, or escalate.
4. Route physical-device risk to Kira, maintenance/patch risk to O'Brien, service-health risk to Julian, and virtual topology risk to Dax.
5. Escalate high-risk or host-changing actions to Sisko and require human approval for critical or security-surface mutations.
6. Record evidence ids before any incident can be closed.

## Protective Action Boundaries

- Monitor and audit are read-only.
- Isolate, quarantine, blocking, service stops, credential rotation, route changes, firewall changes, and privilege changes are active defense.
- Active defense must name the exact target resource and rollback or recovery expectation.
- Critical actions require human approval even when Odo recommends immediate response.

## Required Evidence

- signal id and source
- affected resource id
- severity and confidence
- observed indicator or finding summary
- recommended action
- approval requirement
- response owner
- closure evidence ids

## Security Summary

Odo's compact operator read model is available with:

```bash
PYTHONPATH=src python3 -m overseer.cli security-summary --store state/overseer.sqlite3
```

It summarizes persisted security surfaces, alert audit events, latest host security findings, and protective firewall or block plans without executing active defense.

## IDS Advisory Dispatch

Firewall and source-block plans require an Intrusion Detection advisory package before approval. Overseer can export the advisory prompt and dispatch it to the registered Intrusion Detection Codex thread through the local `codex-projects` registry:

```bash
PYTHONPATH=src python3 -m overseer.cli dispatch-host-security-ids-review-package --store state/overseer.sqlite3 --package-id ids-review.admin.host-security.block-source.8-8-8-8 --dispatched-by odo
```

Dispatch resumes the registered thread when needed, then delivers the advisory prompt into the tmux-backed Codex session. It records prompt path, thread id, conversation id, resume status, and prompt-delivery status. It does not accept the advisory, approve the admin plan, or execute firewall changes; `record-host-security-ids-review-result --status accepted` remains the separate review gate.

## Desired Firewall Policy Enforcement

Odo can turn a reviewed `config/desired-firewall.json` rule into a staged
firewall admin plan through the protected API:

```text
POST /host/security/firewall-policy/enforcement-plans
```

Supported desired rules are objects with `action` set to `allow_tcp` or
`deny_tcp` and a numeric `port`. Staging writes an admin plan and prepares an
IDS review prompt under ignored state. It does not apply firewall rules, reload
firewall services, change routes, alter service bind addresses, or approve the
plan. Human approval remains required after IDS review before enforcement.
