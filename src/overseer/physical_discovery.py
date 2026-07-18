"""Read-only physical path discovery adapter."""

from __future__ import annotations

from pathlib import Path

from .physical import PhysicalAssetKind, PhysicalIdentity


class PathPhysicalDiscoveryAdapter:
    def __init__(self, roots: tuple[str | Path, ...] = ("/dev/serial/by-id", "/dev/serial/by-path")) -> None:
        self.roots = tuple(Path(root) for root in roots)

    def discover(self) -> tuple[PhysicalIdentity, ...]:
        identities: list[PhysicalIdentity] = []
        for root in self.roots:
            if not root.exists() or not root.is_dir():
                continue
            for path in sorted(root.iterdir(), key=lambda item: item.name):
                if path.name.startswith("."):
                    continue
                identities.append(
                    PhysicalIdentity(
                        kind=PhysicalAssetKind.SERIAL_PORT,
                        stable_id=f"serial.{_stable_name(path.name)}",
                        observed_paths=frozenset({str(path)}),
                    )
                )
        return tuple(identities)


def _stable_name(name: str) -> str:
    cleaned = "".join(character.lower() if character.isalnum() else "-" for character in name)
    return "-".join(part for part in cleaned.split("-") if part)
