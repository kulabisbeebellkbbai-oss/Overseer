# Psychlo coordination polling

`overseer-psychlo-coordination-tick.service` runs one bounded bridge `tick` and
exits. Its timer provides the production polling cadence needed to collect
authoritative project-lead and supervisor results after API intake without
keeping a second long-running bridge process.

The service and timer are source artifacts only. They are intentionally not
installed, enabled, or started by this change. Activation remains a separate
Overseer-approved deployment action.

Before staging activation, verify the exact units from the checkout:

```bash
systemd-analyze verify \
  systemd/overseer-psychlo-coordination-tick.service \
  systemd/overseer-psychlo-coordination-tick.timer
```

The unit reads the existing private project bindings and peer credential,
writes only the private bridge database and the configured authoritative
Overseer state directory, and invokes `python3 -m overseer.psychlo_bridge_cli
tick`. Each lead or supervisor dispatcher first derives a stable identity
without an external effect. An immediate database transaction then inserts
that identity in an `uncertain` state with its owner and idempotency key. Only
the process that inserted the immutable intent may submit the prompt; an
existing intent is never taken over or resubmitted, regardless of elapsed
time. A crash before or after submission therefore resumes collection by the
stable identity and fails closed if the external outcome remains uncertain.
Only an authoritative terminal lead or supervisor result advances the
corresponding work record; missing supervisor dispatch configuration leaves
work pending.
