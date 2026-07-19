"""Physical asset identity and checkout helpers."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class PhysicalAssetKind(StrEnum):
    USB_DEVICE = "usb_device"
    SERIAL_PORT = "serial_port"
    COM_PORT = "com_port"
    CONNECTED_DEVICE = "connected_device"
    POWER_RESOURCE = "power_resource"
    STORAGE_ARRAY = "storage_array"
    COMPOSITE = "composite_physical_asset"


class PhysicalIdentitySource(StrEnum):
    OPERATOR_DECLARED = "operator_declared"
    DISCOVERED = "discovered"


@dataclass(frozen=True)
class PhysicalIdentity:
    kind: PhysicalAssetKind
    stable_id: str
    observed_paths: frozenset[str] = field(default_factory=frozenset)
    vendor_id: str | None = None
    product_id: str | None = None
    serial_number: str | None = None
    capabilities: frozenset[str] = field(default_factory=frozenset)
    power_profile: str | None = None
    storage_profile: str | None = None
    exclusive_groups: frozenset[str] = field(default_factory=frozenset)
    depends_on: frozenset[str] = field(default_factory=frozenset)
    source: PhysicalIdentitySource = PhysicalIdentitySource.OPERATOR_DECLARED
    last_observed_at: str | None = None

    def identity_keys(self) -> frozenset[str]:
        keys = {f"stable:{self.stable_id}"}
        keys.update(f"path:{path}" for path in self.observed_paths)
        if self.vendor_id and self.product_id:
            keys.add(f"usb:{self.vendor_id}:{self.product_id}:{self.serial_number or 'no-serial'}")
        if self.serial_number:
            keys.add(f"serial:{self.serial_number}")
        keys.update(f"group:{group}" for group in self.exclusive_groups)
        return frozenset(keys)

    def is_complete_for_exclusive_checkout(self) -> bool:
        if not self.stable_id:
            return False
        if self.kind in {PhysicalAssetKind.USB_DEVICE, PhysicalAssetKind.CONNECTED_DEVICE}:
            return bool((self.vendor_id and self.product_id) or self.serial_number or self.observed_paths)
        if self.kind in {PhysicalAssetKind.SERIAL_PORT, PhysicalAssetKind.COM_PORT}:
            return bool(self.observed_paths)
        if self.kind in {PhysicalAssetKind.POWER_RESOURCE, PhysicalAssetKind.STORAGE_ARRAY}:
            return bool(self.stable_id)
        return bool(self.stable_id)

    def has_power_risk(self) -> bool:
        return bool(self.power_profile and self.power_profile not in {"none", "low"})

    def has_storage_risk(self) -> bool:
        return bool(self.storage_profile and self.storage_profile not in {"none", "read_only"})


def physical_identity_conflicts(left: PhysicalIdentity, right: PhysicalIdentity) -> bool:
    return bool(left.identity_keys() & right.identity_keys() or left.depends_on & ({right.stable_id} | right.depends_on))
