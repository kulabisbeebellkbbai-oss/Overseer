# Persistence

Overseer needs durable coordination state, but runtime databases must remain local and uncommitted. The first persistence slice defines a small SQLite-backed store that only creates a database when an operator passes an explicit path.

## Stored Records

- resources
- claims
- conflict decisions
- approval requests
- audit events

## Boundaries

- Database files are ignored by `.gitignore`.
- The store must not persist secrets, credentials, tokens, personal exports, or raw service payloads.
- Runtime state should live under an ignored operator-selected path such as `state/overseer.sqlite3`.
- The persistence API stores typed records as JSON payloads so the domain model can continue to evolve before schema hardening.

## Next Hardening Steps

- Add migrations before changing on-disk shape.
- Add file permission checks for local stores.
- Add explicit export redaction.
- Add append-only audit storage once live actions exist.
