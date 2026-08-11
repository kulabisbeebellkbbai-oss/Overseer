# Psychlo-derived canary result peer contract

Overseer accepts `POST /psychlo/concurrency/canary-result` only as a
Psychlo-to-Overseer authenticated peer message. The sender must use the
configured peer secret, the exact loopback authority, a fresh nonce and
timestamp, and the complete `concurrency-canary-result` contract. The result
must bind to the persisted approved canary authorization and contain two
successful overlapping executions; a dispatch acknowledgement is not a
result.

Psychlo is the counterpart responsible for producing this message after its
bounded canary completes. Overseer persists the delivered result as a distinct
protocol record. It never accepts a caller-provided result object, lead callback,
or arbitrary protocol row as ceiling evidence. A later ceiling authorization
must reference the exact delivered result ID, target ceiling, revision, and
digest.
