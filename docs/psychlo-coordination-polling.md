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
tick`. Each lead or supervisor dispatch is protected by a database-backed
lease and a stable idempotency key, so concurrent API, CLI, and runtime ticks
cannot dispatch the same operation simultaneously. Before a prompt can be
submitted, the bridge also persists its deterministic dispatch identity in an
`uncertain` state. A crash after submission therefore resumes collection by
that identity and never submits the prompt again. Only an authoritative
terminal lead or supervisor result advances the corresponding work record;
missing supervisor dispatch configuration fails closed and leaves work
pending.
