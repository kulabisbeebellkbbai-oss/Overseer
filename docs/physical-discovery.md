# Physical Discovery

Physical discovery is a read-only adapter for finding device path entries such as `/dev/serial/by-id`. When a discovered serial path resolves to a USB-backed tty, Kira also reads sysfs metadata such as vendor id, product id, and serial number. It does not open devices, flash firmware, change permissions, or claim assets.

## Boundaries

- Discovery inspects directory entries only.
- USB metadata enrichment reads sysfs text files only.
- Discovery does not send descriptor probes or open device nodes.
- Device identity is still incomplete for hardware-sensitive actions until the relevant project-specific verification gate confirms the expected target.
- Any use of a discovered device still requires checkout and the relevant approval gates.
- Discovered path identities are persisted only when an explicit SQLite store path is provided.

## CLI

```bash
PYTHONPATH=src python3 -m overseer.cli discover-physical --root /dev/serial/by-id
PYTHONPATH=src python3 -m overseer.cli discover-physical --root /dev/serial/by-id --store state/overseer.sqlite3
PYTHONPATH=src python3 -m overseer.cli physical-summary --store state/overseer.sqlite3
```

`physical-summary` is Kira's compact read model for persisted physical identities. It reports asset counts, checkout readiness, power risk, storage risk, counts by physical kind, counts by identity source, and per-asset identity detail.

`discover-physical` reports the same identity fields as `physical-summary`, including any read-only USB sysfs metadata that was available at discovery time.

Identity source distinguishes operator-declared records from read-only path discovery:

- `operator_declared` means the asset came from explicit configuration or direct store seeding.
- `discovered` means the asset came from directory discovery and carries a `last_observed_at` timestamp.
