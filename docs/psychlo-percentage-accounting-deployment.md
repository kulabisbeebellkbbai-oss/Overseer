# Psychlo provider-percentage accounting deployment

This source stage does not activate a recurring feed. The meter and delivery
units are static one-shots, and the meter additionally requires the absent
`~/.config/overseer/psychlo-meter/producer-enabled` gate.

## Runtime ownership

Both checked-in units are bound to the already approved, immutable Overseer
runtime:

`~/.local/share/overseer/venvs/psychlo-v1-1-cryptography-46.0.7-86d2f47`

That runtime was provisioned by completed admin plan
`admin.python-hashed-venv.overseer-v1-1-phase-d.20260814`. The unit files bind
the exact directory read-only inside their `ProtectHome=tmpfs` namespaces and
use `~/.local/share/overseer/project/src` as the separately promoted source.

The path is deployment-plan-owned, not a floating current-runtime pointer.
Replacing, deleting, or rotating it requires a new hash-pinned Python-runtime
plan, a new source/unit review that updates both `ExecStart` and
`BindReadOnlyPaths`, and a separately approved unit promotion. Never broaden
the bind to `%h`, `.local`, or `.codex`.

## First-run boundary

The first provider read uses the explicit logged-in one-shot CLI because no
narrow systemd-compatible Codex authentication namespace has been approved.
The static meter unit must remain blocked until such a boundary is implemented
and reviewed. After a successful observation, delivery is a separate approved
one-shot and must produce a durable `inserted` or exact `duplicate` receipt.

The recurring timer remains disabled. Timer enablement, policy activation, and
the first scheduling decision each require their own later approval.
