"""Read-only physical path discovery adapter."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from .physical import PhysicalAssetKind, PhysicalIdentity, PhysicalIdentitySource


class PathPhysicalDiscoveryAdapter:
    def __init__(
        self,
        roots: tuple[str | Path, ...] = ("/dev/serial/by-id", "/dev/serial/by-path"),
        sysfs_tty_root: str | Path = "/sys/class/tty",
    ) -> None:
        self.roots = tuple(Path(root) for root in roots)
        self.sysfs_tty_root = Path(sysfs_tty_root)

    def discover(self) -> tuple[PhysicalIdentity, ...]:
        identities: list[PhysicalIdentity] = []
        observed_at = datetime.now(UTC).isoformat()
        for root in self.roots:
            if not root.exists() or not root.is_dir():
                continue
            for path in sorted(root.iterdir(), key=lambda item: item.name):
                if path.name.startswith("."):
                    continue
                metadata = self._usb_metadata_for_path(path)
                identities.append(
                    PhysicalIdentity(
                        kind=PhysicalAssetKind.SERIAL_PORT,
                        stable_id=f"serial.{_stable_name(path.name)}",
                        observed_paths=frozenset({str(path)}),
                        vendor_id=metadata.get("vendor_id"),
                        product_id=metadata.get("product_id"),
                        serial_number=metadata.get("serial_number"),
                        capabilities=frozenset({"usb"} if metadata else ()),
                        source=PhysicalIdentitySource.DISCOVERED,
                        last_observed_at=observed_at,
                    )
                )
        return tuple(identities)

    def _usb_metadata_for_path(self, path: Path) -> dict[str, str]:
        tty_name = path.resolve(strict=False).name
        if not tty_name:
            return {}
        device = self.sysfs_tty_root / tty_name / "device"
        for candidate in (device, *device.parents):
            if candidate == self.sysfs_tty_root.parent:
                break
            metadata = _read_usb_metadata(candidate)
            if metadata:
                return metadata
        return {}


def _stable_name(name: str) -> str:
    cleaned = "".join(character.lower() if character.isalnum() else "-" for character in name)
    return "-".join(part for part in cleaned.split("-") if part)


def _read_usb_metadata(path: Path) -> dict[str, str]:
    fields = {
        "vendor_id": _read_first_line(path / "idVendor"),
        "product_id": _read_first_line(path / "idProduct"),
        "serial_number": _read_first_line(path / "serial"),
    }
    return {key: value for key, value in fields.items() if value}


def _read_first_line(path: Path) -> str | None:
    try:
        text = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if not text:
        return None
    return text.splitlines()[0].strip()
