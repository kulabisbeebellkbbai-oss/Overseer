# Coordinator Service

The coordinator service is the first application-level layer above the registry and store. It wires together command decisions, persisted claim state, approval requests, and audit events.

## Responsibilities

- register resources in memory and optional persistence
- request claims through the command model
- persist claims and decisions
- create approval requests for escalated decisions
- create audit events for every claim decision
- activate approved claims
- release claims and update stored state

## Boundaries

- The service does not execute package installs, firewall changes, service restarts, device access, or health probes; those run through dedicated runtime and admin adapter paths.
- Persistence is optional and must be passed explicitly.
- Approval records are created and approved through explicit operator or API actions before any mutation-specific executor can act.
