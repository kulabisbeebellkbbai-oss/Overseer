"""Read-only virtual asset discovery from local listener evidence."""

from __future__ import annotations

from dataclasses import dataclass

from .core import OwnerDomain, Resource, ResourceState, ResourceType, RiskLevel
from .host import HostInspectionAdapter, HostInspectionSnapshot


@dataclass(frozen=True)
class TcpListener:
    local: str
    address: str
    port: int
    evidence: str


class ListenerVirtualDiscoveryAdapter:
    def __init__(self, host_inspection_adapter: HostInspectionAdapter | None = None) -> None:
        self.host_inspection_adapter = host_inspection_adapter or HostInspectionAdapter()

    def discover(self, snapshot: HostInspectionSnapshot | None = None) -> tuple[Resource, ...]:
        inspected = snapshot or self.host_inspection_adapter.inspect()
        try:
            ss_output = inspected.observation("ss").stdout
        except KeyError:
            return ()
        resources: dict[str, Resource] = {}
        for listener in parse_tcp_listeners(ss_output):
            resource = resource_from_tcp_listener(listener, inspected.id, inspected.captured_at)
            resources[resource.id] = resource
        return tuple(resources[key] for key in sorted(resources))


def parse_tcp_listeners(ss_output: str) -> tuple[TcpListener, ...]:
    listeners: list[TcpListener] = []
    seen: set[tuple[str, int]] = set()
    for line in ss_output.splitlines():
        if "LISTEN" not in line:
            continue
        columns = line.split()
        if len(columns) < 4:
            continue
        local = columns[3]
        address, port = _split_address_port(local)
        if not port.isdigit():
            continue
        key = (address, int(port))
        if key in seen:
            continue
        seen.add(key)
        listeners.append(TcpListener(local=local, address=address, port=int(port), evidence=line.strip()))
    return tuple(listeners)


def resource_from_tcp_listener(listener: TcpListener, snapshot_id: str, captured_at: str) -> Resource:
    bind_scope = _bind_scope(listener.address)
    return Resource(
        id=f"listener.tcp.{_safe_id(listener.address)}.{listener.port}",
        name=f"TCP {listener.local}",
        type=ResourceType.VIRTUAL_ASSET,
        owner_domain=OwnerDomain.DAX,
        risk_level=_listener_risk(bind_scope),
        state=ResourceState.AVAILABLE,
        identifiers={
            "kind": "gateway" if bind_scope == "all_interfaces" else "proxy",
            "host": listener.address,
            "ports": [listener.port],
            "protocol": "tcp",
            "bind_scope": bind_scope,
            "snapshot_id": snapshot_id,
            "process_hint": listener.evidence,
        },
        exclusive_groups=frozenset({f"tcp.{listener.port}", f"tcp.{_safe_id(listener.address)}.{listener.port}"}),
        last_verified_at=captured_at,
        notes="discovered from read-only listener evidence",
    )


def _listener_risk(bind_scope: str) -> RiskLevel:
    if bind_scope == "all_interfaces":
        return RiskLevel.HIGH
    if bind_scope == "non_loopback":
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def _bind_scope(address: str) -> str:
    if address in {"0.0.0.0", "*", "[::]", "::"}:
        return "all_interfaces"
    if address in {"127.0.0.1", "::1", "[::1]", "localhost"}:
        return "loopback"
    return "non_loopback"


def _split_address_port(local_socket: str) -> tuple[str, str]:
    if local_socket.startswith("[") and "]:" in local_socket:
        address, port = local_socket.rsplit("]:", 1)
        return f"{address}]", port
    if ":" not in local_socket:
        return local_socket, ""
    address, port = local_socket.rsplit(":", 1)
    return address, port


def _safe_id(value: str) -> str:
    cleaned = "".join(character.lower() if character.isalnum() else "-" for character in value)
    return "-".join(part for part in cleaned.split("-") if part) or "any"
