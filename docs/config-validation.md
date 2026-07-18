# Config Validation

Config validation rejects common unsafe or inconsistent seed data before it reaches a store.

## Validation Rules

- Resource ids must be unique.
- Usage-limit ids must be unique.
- Usage limits must reference configured resources when loaded in the same config.
- Capacity and remaining values cannot be negative.
- Remaining capacity cannot exceed total capacity.
- Secret-like keys are rejected in config payloads.

## Secret-Like Keys

Do not include keys such as:

- token
- secret
- password
- credential
- api_key
- private_key
