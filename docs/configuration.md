# Configuration

Overseer configuration lets an operator seed known resources, usage limits, health targets, and known physical identities without live discovery. Configuration is explicit JSON data, not a secret store and not a runtime database export.

## Supported Sections

- `resources`
- `usage_limits`
- `health_targets`
- `physical_identities`

## Boundaries

- Do not put credentials, tokens, personal exports, or raw service payloads in config files.
- Config loading does not probe the host.
- Config loading does not discover or probe devices that were not explicitly described by the operator.
- Config loading should be combined with runtime identity checks before physical or security-sensitive use.
- Physical identities loaded from config default to source `operator_declared`.
