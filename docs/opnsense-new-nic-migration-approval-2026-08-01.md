# OPNsense New-NIC Migration Approval Package

Status: the explicitly approved, instance-scoped NordVPN recovery was attempted.
No firewall, routing, interface, IDS, DNS/DHCP, credential, endpoint, or
service-bind configuration was changed.

## Current State

- Firewall: OPNsense at `10.50.0.1`.
- Previous physical assignments from the July 26 backup:
  - WAN: `em0`
  - LAN: `re1`
- Current physical assignments:
  - WAN: `re3`, DHCP address `192.168.68.107/24`, gateway
    `192.168.68.1`, link up at 1 Gb/s
  - LAN: `re2`, static address `10.50.0.1/24`, link up at 1 Gb/s
- The retired `em0` and former LAN port `re1` are unassigned and have no
  carrier. The disabled `OPT1` placeholder remains assigned to `re0` and is
  unchanged.
- The current exported OPNsense configuration contains no `em0` or `re1`
  references. Firewall rules use logical interfaces (`LAN`, `WAN`,
  `WIFI_OUTSIDE`, and `openvpn`); outbound NAT is automatic.
- WAN gateway `WAN_DHCP` is online. Unbound, dnsmasq DNS/DHCP, packet filter,
  routing, all three OpenVPN processes, Suricata, and syslog-ng are running.
- Suricata is enabled in netmap IPS mode on logical `WAN` and
  `WIFI_OUTSIDE`, so its configured interface selection follows the logical
  WAN assignment to `re3`.
- The NordVPN OpenVPN client process is running but its session is
  `reconnecting` with zero bytes transferred. Gateway
  `NORDVPN_V4_EXPLICIT` is offline with 100% monitor loss. The two inbound
  OpenVPN servers report healthy.
- The system status reports a non-persistent crash report from approximately
  the migration/reboot window; this requires review but does not itself prove
  a network-service fault.
- The workstation still has `10.50.0.100/24` on `enp3s0`. The IDS receiver
  remains bound to `10.50.0.100:5514/udp` and `10.50.0.100:8088/tcp`, and the
  protected gateway remains bound to `10.50.0.100:9443/tcp`.

## Intended Traffic and Policy

The migration is identity-preserving: no subnet, firewall-policy, service
address, VPN identity, public exposure, port-forward, or client authorization
change is intended.

- LAN clients: `10.50.0.0/24` through logical `LAN` on `re2`.
- WAN/upstream: OPNsense through logical `WAN` on `re3` to
  `192.168.68.1`.
- OutsideLab: `10.60.0.0/24` through `WIFI_OUTSIDE`, with its existing
  private-network blocks and NordVPN-only Internet kill switch preserved.
- Lab remote access VPN: `10.70.0.0/24` with existing narrow protected
  gateway rules and logging preserved.
- OutsideLab remote access VPN: `10.71.0.0/24` to `10.60.0.0/24` only.
- IDS/syslog: Suricata on logical `WAN` and `WIFI_OUTSIDE`, forwarding to
  `10.50.0.100:5514/udp`.

## Proposed Approved Actions

1. Save a fresh, permission-restricted OPNsense configuration backup before
   any mutation.
2. Preserve the current assignments exactly: `LAN -> re2` and `WAN -> re3`.
   Do not change `OPT1`, `WIFI_OUTSIDE`, `VPN_NORD`, OpenVPN, VLANs, addresses,
   subnets, or client identities.
3. Reconfigure the NordVPN OpenVPN client instance only. If a simple instance
   restart restores the tunnel, stop there; do not alter credentials, remote
   endpoint, cryptography, or policy.
4. Verify the NordVPN client session is connected, has nonzero traffic, and
   `NORDVPN_V4_EXPLICIT` is online. Verify an OutsideLab client has Internet
   access through the VPN and still cannot reach RFC1918 networks.
5. Reapply the existing packet-filter configuration only if runtime evidence
   still contains active references to `em0` or `re1`, or if the Nord gateway
   remains stale after the client reconnects. Do not edit rule contents or
   order.
6. Reconfigure Suricata only if its runtime capture state does not show the
   logical WAN on `re3`. Do not change enabled rules, policy, mode, or monitored
   logical interfaces.
7. Reconfigure syslog, Unbound, and dnsmasq only if their health or traffic
   checks fail. Do not change destinations, zones, host overrides, DHCP scope,
   leases, or resolver policy.
8. Review and retain a redacted summary of the crash report. Do not upload or
   delete it as part of this approval.

No new firewall or IDS rules are proposed because the logical interface names,
addresses, traffic intent, and security boundaries are unchanged. Default deny
and the existing logged whitelist rules remain authoritative.

## Validation

- Confirm `re2` and `re3` remain up with zero interface errors.
- Confirm `10.50.0.1`, DNS, DHCP, NTP, and Internet access from LAN.
- Confirm WAN DHCP and gateway health.
- Confirm both inbound OpenVPN servers and authorized protected-gateway access.
- Confirm the NordVPN client and explicit gateway recover.
- Confirm OutsideLab kill-switch and RFC1918 isolation with allowed and denied
  flow evidence.
- Confirm Suricata remains running on logical WAN/WIFI_OUTSIDE and the receiver
  obtains a fresh event or heartbeat.
- Confirm the protected gateway and IDS receiver retain their existing binds.
- Confirm the active OPNsense configuration and runtime contain no stale
  `em0`/`re1` dependencies.

## Risks and Rollback

- A VPN restart briefly interrupts OutsideLab Internet; the existing kill
  switch should fail closed.
- A packet-filter reapply can interrupt active sessions, including remote VPN
  sessions.
- An IDS reconfigure can briefly reduce inspection coverage.
- DNS/DHCP reconfiguration can briefly affect client name resolution or lease
  service.

Rollback is to restore the pre-change backup, reapply only the affected
service, and verify management access from LAN. Physical rollback, if required,
is `WAN -> em0` and `LAN -> re1`, followed by cable restoration; it must be
performed locally/console-side to avoid lockout. If only NordVPN recovery is
attempted, rollback is to restore that instance's unchanged pre-action
configuration and restart only that instance.

## Approval Boundary

This package authorizes nothing by itself. Explicit user approval is required
before any OpenVPN restart/reconfigure, packet-filter apply, route/gateway
reconfigure, IDS reconfigure, DNS/DHCP reconfigure, interface assignment, or
configuration restore.

## Intrusion Detection Review Request

Evaluate this package before enforcement. Assess mitigation, inspection,
logging, alerting, policy/rule gaps, rollback and lockout risk, whether custom
firewall or IDS rules are required, whether the conditional service
reconfiguration is appropriately bounded, and whether the NordVPN failure
should be diagnosed further before any restart. Do not apply, reload, restart,
or enable any firewall, routing, VPN, NAT, IDS/IPS, DNS/DHCP, service-bind, or
alerting change.

## Approved Recovery Result

The user approved the scoped NordVPN recovery and validation on August 1,
2026.

- Created a fresh OPNsense configuration backup at
  `/home/god/.codex/backups/opnsense/20260801T211000Z-pre-nordvpn-nic-migration-recovery.xml`
  with mode `0600`; XML validation passed.
- Restarted only OpenVPN instance
  `de1a8e2f-2757-496c-8466-576ec432d215`; the API returned `result: ok`.
- The client did not recover. It remains `reconnecting`, with no virtual or
  real address and zero transferred bytes. `NORDVPN_V4_EXPLICIT` remains
  offline with 100% monitor loss.
- The current firewall state and accessible firewall/OpenVPN log APIs show no
  traffic to or from the configured NordVPN remote endpoint. The accessible
  OpenVPN log endpoint returned no records, so the failure cannot yet be
  distinguished among client configuration, authentication, routing/source
  selection, or remote endpoint reachability from the available evidence.
- WAN `re3` and LAN `re2` remain up at 1 Gb/s with zero reported input/output
  errors. `WAN_DHCP` remains online.
- Packet filtering, routing, dnsmasq, Unbound, both inbound OpenVPN servers,
  Suricata, and syslog-ng remain running.
- The current backup contains no stale `em0` or `re1` interface assignments.
- The OutsideLab RFC1918 blocks, IPv6 block, VPN-only pass rule, and final
  kill-switch rule remain enabled and ordered at sequences 40 through 90.
- IDS receiver health at `10.50.0.100:8088`, DNS resolution for
  `roadex.home.arpa`, and protected-gateway reachability at
  `10.50.0.100:9443` passed.

Per the approval boundary, work stopped without reapplying the packet filter,
reconfiguring routing/IDS/DNS/DHCP, changing the NordVPN endpoint or
credentials, or changing any interface assignment. A further diagnostic or
repair plan requires separate approval.

## Deferred NordVPN Work

On August 1, 2026, the user deferred all further NordVPN diagnosis and repair
until the Protected Service Gateway and its required applications are up and
running on MSI.

Until that prerequisite is explicitly confirmed:

- Do not restart, reconfigure, replace, or troubleshoot the NordVPN client.
- Do not change `NORDVPN_V4_EXPLICIT`, the NordVPN remote endpoint,
  credentials, routes, NAT, DNS, firewall rules, IDS policy, or interface
  assignments for this issue.
- Preserve the OutsideLab private-network blocks and final kill switch so the
  failed VPN path remains fail-closed.
- Treat MSI gateway-and-app readiness as a dependency, not as authorization to
  resume work. Resuming NordVPN diagnosis or mutation still requires an
  explicit user request and any applicable approval review.

Resume prerequisite: verified evidence that the Protected Service Gateway and
its required applications are running successfully on MSI through the intended
gateway path.
