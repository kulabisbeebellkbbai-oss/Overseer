# Configuration

Overseer configuration lets an operator seed known resources and usage limits without live discovery. Configuration is explicit JSON data, not a secret store and not a runtime database export.

## Supported Sections

- `resources`
- `usage_limits`
- `health_targets`

## Boundaries

- Do not put credentials, tokens, personal exports, or raw service payloads in config files.
- Config loading does not probe the host.
- Config loading does not register devices that were not explicitly described by the operator.
- Config loading should be combined with runtime identity checks before physical or security-sensitive use.
