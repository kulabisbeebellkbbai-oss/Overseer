# Physical Discovery

Physical discovery is a read-only adapter for finding device path entries such as `/dev/serial/by-id`. It does not open devices, flash firmware, change permissions, or claim assets.

## Boundaries

- Discovery inspects directory entries only.
- Discovery does not probe USB descriptors beyond the path names supplied by the filesystem.
- Device identity is still incomplete until Kira's stronger identity checks are added.
- Any use of a discovered device still requires checkout and the relevant approval gates.
- Discovered path identities are persisted only when an explicit SQLite store path is provided.

## CLI

```bash
PYTHONPATH=src python3 -m overseer.cli discover-physical --root /dev/serial/by-id
PYTHONPATH=src python3 -m overseer.cli discover-physical --root /dev/serial/by-id --store state/overseer.sqlite3
```
