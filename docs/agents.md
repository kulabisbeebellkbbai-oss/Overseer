# Overseer Agent Roles

Overseer agents are organized around a Deep Space 9 inspired command crew. These names describe responsibility boundaries, not external service accounts.

## Sisko

Command manager and coordinator.

- Owns overall prioritization, escalation, and command decisions.
- Routes work across physical assets, virtual assets, service health, maintenance, usage limits, and security.
- Requires explicit approval for high-risk actions.
- Keeps ownership, blockers, and handoffs visible.

## Kira

Physical asset manager.

- Manages checkout and deconfliction for USB, serial, COM ports, and connected devices.
- Tracks power-sensitive resources and storage arrays.
- Verifies device identity before use where identity matters.
- Blocks conflicting physical-device work until ownership is released or reassigned.

## O'Brien

Maintenance and patch deployment lead.

- Handles maintenance schedules, software installs, updates, and patch deployment.
- Coordinates restart windows and service interruption risk.
- Requires rollback plans for risky changes.
- Records post-change verification evidence.

## Odo

Security monitor and active defense lead.

- Watches for possible intrusions and security posture drift.
- Runs or schedules security audits.
- Coordinates protective actions during active threats.
- Escalates defensive changes through explicit approval gates.

## Quark

Service-level and usage-limit manager.

- Monitors services with quotas, timeouts, credits, or usage limits.
- Tracks renewal windows and schedules continuation work.
- Prevents work from wasting limited service capacity.
- Surfaces service-level constraints before a thread starts work.

## Dax

Virtual asset checkout and deconfliction lead.

- Manages emulators, VMs, gateways, proxies, and other virtual resources.
- Tracks active leases and ownership.
- Prevents conflicting virtual topology or proxy changes.
- Coordinates shared virtual-resource scheduling.

## Julian

Service health and efficiency monitor.

- Monitors MCP service errors, hosted page errors, HTTPS failures, HTML failures, and JSON failures.
- Tracks service health and efficiency evidence.
- Reports exact failing paths and likely owners.
- Confirms recovery before health-related work is closed.
