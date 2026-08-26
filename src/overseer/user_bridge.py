"""A narrowly scoped, read-only bridge from the ``god`` user to Overseer.

The bridge deliberately owns its transport and protocol boundary.  It has no
Codex, tmux, shell, network, or credential imports. A deployment may inject
projection providers into :class:`UserBridge`; the socket-activated entry
point wires only the two fixed read-only providers reviewed for v1.1.6.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import socket
import stat
import struct
import threading
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping


BRIDGE_PROTOCOL = "overseer.user-bridge.v1"
# The installed system account's UID is substituted into the systemd unit at
# activation.  Tests and embedders must pass their dedicated numeric UID.
DEFAULT_OVERSEER_UID = 987
MAX_REQUEST_BYTES = 16 * 1024
MAX_RESPONSE_BYTES = 64 * 1024
MAX_REQUEST_ID_LENGTH = 128
MAX_STRING_LENGTH = 256
MAX_SESSIONS = 64
MAX_USAGE_WINDOWS = 8
MAX_REPLAY_ENTRIES = 256
DEFAULT_PROVIDER_TIMEOUT = 2.0
REQUEST_TIMEOUT_SECONDS = 3.0
DEFAULT_USER_BRIDGE_SOCKET = Path("/run/overseer/codex-user-bridge.sock")
MAX_ACTIVE_CONNECTIONS = 8
MAX_PROVIDER_WORKERS = 2

_REQUEST_FIELDS = frozenset({"protocol", "request_id", "method", "params"})
_METHODS = frozenset({"codex.sessions.list.v1", "codex.usage.snapshot.v1"})
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SAFE_CODE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_STATES = frozenset({"available", "stale", "unavailable", "error"})
_SESSION_FIELDS = frozenset({"session_id", "project_id", "status", "last_seen_at"})
_USAGE_FIELDS = frozenset({"name", "used", "remaining", "reset_at"})

ProjectionProvider = Callable[[], Mapping[str, Any]]


class UserBridgeProtocolError(ValueError):
    """A request or bridge configuration violates the closed contract."""


class UserBridgeClientError(ConnectionError):
    """Base error for client-side transport and response failures."""


class UserBridgeUnavailableError(UserBridgeClientError):
    """The fixed bridge socket is unavailable or cannot be connected."""


class UserBridgeTimeoutError(UserBridgeClientError):
    """The bridge did not complete bounded I/O before the deadline."""


class UserBridgePeerError(UserBridgeClientError):
    """Socket metadata or peer credentials do not match the expected owner."""


class UserBridgeResponseError(UserBridgeClientError):
    """The server response violates the closed response contract."""


@dataclass(frozen=True)
class PeerCredentials:
    pid: int
    uid: int
    gid: int


def peer_credentials(connection: socket.socket) -> PeerCredentials:
    """Read Linux peer credentials without trusting caller-supplied metadata."""

    try:
        raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    except (AttributeError, OSError) as exc:
        raise UserBridgeProtocolError("peer credentials unavailable") from exc
    if len(raw) != struct.calcsize("3i"):
        raise UserBridgeProtocolError("peer credentials malformed")
    pid, uid, gid = struct.unpack("3i", raw)
    if pid <= 0 or uid < 0 or gid < 0:
        raise UserBridgeProtocolError("peer credentials invalid")
    return PeerCredentials(pid=pid, uid=uid, gid=gid)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise UserBridgeProtocolError("duplicate_field")
        result[key] = value
    return result


def _json_loads(payload: bytes, *, max_bytes: int = MAX_REQUEST_BYTES, too_large_code: str = "request_too_large") -> Any:
    if len(payload) > max_bytes:
        raise UserBridgeProtocolError(too_large_code)
    try:
        text = payload.decode("utf-8")
        return json.loads(text, object_pairs_hook=_reject_duplicate_keys, parse_constant=_reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, UserBridgeProtocolError) as exc:
        if isinstance(exc, UserBridgeProtocolError):
            raise
        raise UserBridgeProtocolError("invalid_json") from exc


def _reject_constant(value: str) -> Any:
    raise UserBridgeProtocolError("invalid_json")


def _safe_string(value: Any, *, code: bool = False) -> str | None:
    if not isinstance(value, str) or not value or len(value) > MAX_STRING_LENGTH:
        return None
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        return None
    if code and _SAFE_CODE_RE.fullmatch(value) is None:
        return None
    return value


def _safe_timestamp(value: Any) -> str | None:
    text = _safe_string(value)
    if text is None or "/" in text or "\\" in text:
        return None
    return text


def _safe_identifier(value: Any) -> str | None:
    text = _safe_string(value)
    if text is None or "/" in text or "\\" in text or text in {".", ".."}:
        return None
    return text


def _safe_nonnegative_integer(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > 10**12:
        return None
    return value


def _error_response(request_id: str | None, code: str) -> bytes:
    response = {
        "protocol": BRIDGE_PROTOCOL,
        "request_id": request_id,
        "status": "error",
        "error": {"code": code, "message": code},
    }
    return _encode_response(response)


def _encode_response(response: Mapping[str, Any]) -> bytes:
    encoded = json.dumps(response, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_RESPONSE_BYTES:
        return _error_response(response.get("request_id"), "response_too_large")
    return encoded


class UserBridge:
    """Serve the two read-only user projections over an authenticated socket."""

    def __init__(
        self,
        *,
        allowed_peer_uid: int = DEFAULT_OVERSEER_UID,
        sessions_provider: ProjectionProvider | None = None,
        usage_provider: ProjectionProvider | None = None,
        provider_timeout: float = DEFAULT_PROVIDER_TIMEOUT,
        replay_entries: int = MAX_REPLAY_ENTRIES,
        max_active_connections: int = MAX_ACTIVE_CONNECTIONS,
        max_provider_workers: int = MAX_PROVIDER_WORKERS,
    ) -> None:
        if isinstance(allowed_peer_uid, bool) or not isinstance(allowed_peer_uid, int) or allowed_peer_uid < 0:
            raise UserBridgeProtocolError("peer uid must be a nonnegative integer")
        if not isinstance(provider_timeout, (int, float)) or isinstance(provider_timeout, bool) or not math.isfinite(provider_timeout) or provider_timeout <= 0:
            raise UserBridgeProtocolError("provider timeout must be positive")
        if isinstance(replay_entries, bool) or not isinstance(replay_entries, int) or replay_entries <= 0:
            raise UserBridgeProtocolError("replay entries must be positive")
        if isinstance(max_active_connections, bool) or not isinstance(max_active_connections, int) or max_active_connections <= 0:
            raise UserBridgeProtocolError("active connections must be positive")
        if isinstance(max_provider_workers, bool) or not isinstance(max_provider_workers, int) or max_provider_workers <= 0:
            raise UserBridgeProtocolError("provider workers must be positive")
        self.allowed_peer_uid = allowed_peer_uid
        self.sessions_provider = sessions_provider
        self.usage_provider = usage_provider
        self.provider_timeout = float(provider_timeout)
        self.replay_entries = replay_entries
        self.max_active_connections = max_active_connections
        self.max_provider_workers = max_provider_workers
        self._replay: OrderedDict[str, tuple[str, bytes]] = OrderedDict()
        self._lock = threading.RLock()
        self._connection_slots = threading.BoundedSemaphore(max_active_connections)
        self._provider_slots = threading.BoundedSemaphore(max_provider_workers)

    def handle_bytes(self, payload: bytes, *, peer_uid: int) -> bytes:
        """Validate and execute one complete request, returning one response."""

        if not isinstance(peer_uid, int) or peer_uid != self.allowed_peer_uid:
            return _error_response(None, "peer_not_allowed")
        if len(payload) > MAX_REQUEST_BYTES:
            return _error_response(None, "request_too_large")

        request_id: str | None = None
        try:
            request_data = _json_loads(payload)
        except UserBridgeProtocolError as exc:
            code = str(exc) if str(exc) in {"request_too_large", "invalid_json", "duplicate_field", "unknown_field", "invalid_request", "unsupported_method"} else "invalid_request"
            return _error_response(request_id, code)

        digest = hashlib.sha256(payload).hexdigest()
        with self._lock:
            if isinstance(request_data, dict):
                candidate_id = request_data.get("request_id")
                if isinstance(candidate_id, str) and _REQUEST_ID_RE.fullmatch(candidate_id):
                    request_id = candidate_id
            cached = self._replay.get(request_id)
            if cached is not None:
                cached_digest, cached_response = cached
                if cached_digest == digest:
                    return cached_response
                return _error_response(request_id, "request_id_reuse")
            try:
                request_id = self._validate_request(request_data)
            except UserBridgeProtocolError as exc:
                code = str(exc) if str(exc) in {"unknown_field", "duplicate_field", "invalid_request", "unsupported_method"} else "invalid_request"
                return _error_response(request_id, code)
            response = self._execute(request_data)
            encoded = _encode_response(response)
            self._replay[request_id] = (digest, encoded)
            self._replay.move_to_end(request_id)
            while len(self._replay) > self.replay_entries:
                self._replay.popitem(last=False)
            return encoded


    def _validate_request(self, value: Any) -> str:
        if not isinstance(value, dict):
            raise UserBridgeProtocolError("invalid_request")
        unknown = set(value) - _REQUEST_FIELDS
        if unknown:
            raise UserBridgeProtocolError("unknown_field")
        if set(value) != _REQUEST_FIELDS:
            raise UserBridgeProtocolError("invalid_request")
        if value.get("protocol") != BRIDGE_PROTOCOL:
            raise UserBridgeProtocolError("invalid_request")
        request_id = value.get("request_id")
        if not isinstance(request_id, str) or _REQUEST_ID_RE.fullmatch(request_id) is None:
            raise UserBridgeProtocolError("invalid_request")
        method = value.get("method")
        if method not in _METHODS:
            raise UserBridgeProtocolError("unsupported_method")
        params = value.get("params")
        if not isinstance(params, dict):
            raise UserBridgeProtocolError("invalid_request")
        if params:
            raise UserBridgeProtocolError("unknown_field")
        return request_id

    def _execute(self, request_data: dict[str, Any]) -> dict[str, Any]:
        request_id = request_data["request_id"]
        method = request_data["method"]
        provider = self.sessions_provider if method == "codex.sessions.list.v1" else self.usage_provider
        projection = self._run_provider(provider, method)
        return {
            "protocol": BRIDGE_PROTOCOL,
            "request_id": request_id,
            "method": method,
            "status": "ok",
            "projection": projection,
        }

    def _run_provider(self, provider: ProjectionProvider | None, method: str) -> dict[str, Any]:
        if provider is None:
            return {"state": "unavailable", "reason": "provider_not_configured"}
        if not self._provider_slots.acquire(blocking=False):
            return {"state": "error", "error_code": "busy"}
        result: dict[str, Any] = {}
        failure: list[BaseException] = []
        done = threading.Event()

        def invoke() -> None:
            try:
                candidate = provider()
                if not isinstance(candidate, Mapping):
                    raise UserBridgeProtocolError("provider_result_invalid")
                result["value"] = dict(candidate)
            except BaseException as exc:  # provider failures never cross the boundary
                failure.append(exc)
            finally:
                done.set()

        def run_provider() -> None:
            try:
                invoke()
            finally:
                self._provider_slots.release()

        try:
            threading.Thread(target=run_provider, name="overseer-user-bridge-provider", daemon=True).start()
        except BaseException:
            self._provider_slots.release()
            return {"state": "error", "error_code": "busy"}
        if not done.wait(self.provider_timeout):
            return {"state": "error", "error_code": "provider_timeout"}
        if failure:
            return {"state": "error", "error_code": "provider_error"}
        try:
            return self._sanitize_projection(result["value"], method)
        except UserBridgeProtocolError:
            return {"state": "error", "error_code": "provider_result_invalid"}

    def _sanitize_projection(self, value: Mapping[str, Any], method: str) -> dict[str, Any]:
        state = value.get("state")
        if state not in _STATES:
            raise UserBridgeProtocolError("provider_result_invalid")
        projection: dict[str, Any] = {"state": state}
        observed_at = _safe_timestamp(value.get("observed_at"))
        stale_at = _safe_timestamp(value.get("stale_at"))
        reason = _safe_string(value.get("reason"), code=True)
        error_code = _safe_string(value.get("error_code"), code=True)
        if observed_at is not None:
            projection["observed_at"] = observed_at
        if stale_at is not None and state == "stale":
            projection["stale_at"] = stale_at
        if reason is not None and state in {"stale", "unavailable"}:
            projection["reason"] = reason
        if error_code is not None and state == "error":
            projection["error_code"] = error_code

        if state in {"available", "stale"}:
            field = "sessions" if method == "codex.sessions.list.v1" else "windows"
            candidates = value.get(field, [])
            if not isinstance(candidates, list):
                raise UserBridgeProtocolError("provider_result_invalid")
            limit = MAX_SESSIONS if field == "sessions" else MAX_USAGE_WINDOWS
            allowed = _SESSION_FIELDS if field == "sessions" else _USAGE_FIELDS
            items: list[dict[str, Any]] = []
            for candidate in candidates[:limit]:
                if not isinstance(candidate, Mapping):
                    continue
                item: dict[str, Any] = {}
                for key in allowed:
                    if key not in candidate:
                        continue
                    if field == "sessions":
                        if key in {"session_id", "project_id", "status"}:
                            text = _safe_string(candidate[key], code=True) if key == "status" else _safe_identifier(candidate[key])
                        else:
                            text = _safe_timestamp(candidate[key])
                        if text is not None:
                            item[key] = text
                    else:
                        if key in {"name", "reset_at"}:
                            text = _safe_string(candidate[key], code=key == "name") if key == "name" else _safe_timestamp(candidate[key])
                            if text is not None:
                                item[key] = text
                        else:
                            number = _safe_nonnegative_integer(candidate[key])
                            if number is not None:
                                item[key] = number
                if item:
                    items.append(item)
            projection[field] = items
        return projection

    def serve_forever(self, listener: socket.socket) -> None:
        """Serve newline-delimited requests from a systemd socket-activated listener."""

        listener.settimeout(REQUEST_TIMEOUT_SECONDS)
        while True:
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            self._dispatch_connection(connection)

    def _dispatch_connection(self, connection: socket.socket) -> None:
        if not self._connection_slots.acquire(blocking=False):
            try:
                connection.settimeout(REQUEST_TIMEOUT_SECONDS)
                connection.sendall(_error_response(None, "busy") + b"\n")
            except OSError:
                pass
            finally:
                connection.close()
            return
        try:
            threading.Thread(
                target=self._connection_worker,
                args=(connection,),
                name="overseer-user-bridge-connection",
                daemon=True,
            ).start()
        except BaseException:
            self._connection_slots.release()
            connection.close()

    def _connection_worker(self, connection: socket.socket) -> None:
        try:
            self._serve_connection(connection)
        finally:
            self._connection_slots.release()

    def _serve_connection(self, connection: socket.socket) -> None:
        try:
            connection.settimeout(REQUEST_TIMEOUT_SECONDS)
            credentials = peer_credentials(connection)
            payload = _read_line(connection)
            response = self.handle_bytes(payload, peer_uid=credentials.uid)
            connection.sendall(response + b"\n")
        except (OSError, UserBridgeProtocolError):
            try:
                connection.sendall(_error_response(None, "request_timeout") + b"\n")
            except OSError:
                pass
        finally:
            connection.close()


class UserBridgeClient:
    """Strict client for the root-created, fixed Unix bridge socket."""

    def __init__(
        self,
        socket_path: str | Path = DEFAULT_USER_BRIDGE_SOCKET,
        *,
        expected_server_uid: int,
        timeout: float = REQUEST_TIMEOUT_SECONDS,
    ) -> None:
        path = Path(socket_path)
        if not path.is_absolute():
            raise UserBridgeUnavailableError("bridge socket path must be absolute")
        if isinstance(expected_server_uid, bool) or not isinstance(expected_server_uid, int) or expected_server_uid < 0:
            raise UserBridgePeerError("expected server uid is invalid")
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not math.isfinite(timeout) or timeout <= 0:
            raise UserBridgeTimeoutError("client timeout is invalid")
        self.socket_path = path
        self.expected_server_uid = expected_server_uid
        self.timeout = float(timeout)

    def call(self, method: str, request_id: str, params: Mapping[str, Any] | None = None) -> dict[str, Any]:
        if method not in _METHODS:
            raise UserBridgeResponseError("unsupported method")
        if not isinstance(request_id, str) or _REQUEST_ID_RE.fullmatch(request_id) is None:
            raise UserBridgeResponseError("invalid request id")
        if params is not None and (not isinstance(params, Mapping) or dict(params)):
            raise UserBridgeResponseError("bridge params must be empty")
        payload = json.dumps(
            {
                "protocol": BRIDGE_PROTOCOL,
                "request_id": request_id,
                "method": method,
                "params": {},
            },
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(payload) > MAX_REQUEST_BYTES:
            raise UserBridgeResponseError("request too large")

        metadata = self._socket_metadata()
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            connection.settimeout(self.timeout)
            try:
                connection.connect(str(self.socket_path))
            except socket.timeout as exc:
                raise UserBridgeTimeoutError("bridge connect timed out") from exc
            except OSError as exc:
                raise UserBridgeUnavailableError("bridge socket unavailable") from exc
            self._verify_socket_metadata(metadata)
            try:
                credentials = peer_credentials(connection)
            except UserBridgeProtocolError as exc:
                raise UserBridgePeerError("bridge server credentials unavailable") from exc
            if credentials.uid != self.expected_server_uid:
                raise UserBridgePeerError("bridge server uid is not approved")
            try:
                connection.sendall(payload + b"\n")
                response_payload = _read_line(connection, limit=MAX_RESPONSE_BYTES, too_large_code="response_too_large")
            except socket.timeout as exc:
                raise UserBridgeTimeoutError("bridge response timed out") from exc
            except UserBridgeProtocolError as exc:
                raise UserBridgeResponseError(str(exc)) from exc
            return self._validate_response(response_payload, request_id, method)
        finally:
            connection.close()

    def _socket_metadata(self) -> tuple[int, int]:
        try:
            metadata = os.lstat(self.socket_path)
        except OSError as exc:
            raise UserBridgeUnavailableError("bridge socket unavailable") from exc
        if not stat.S_ISSOCK(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise UserBridgePeerError("bridge path is not a socket")
        if metadata.st_uid != self.expected_server_uid:
            raise UserBridgePeerError("bridge socket owner is not approved")
        if metadata.st_mode & 0o007:
            raise UserBridgePeerError("bridge socket is accessible to other users")
        return metadata.st_dev, metadata.st_ino

    def _verify_socket_metadata(self, expected: tuple[int, int]) -> None:
        try:
            current = os.lstat(self.socket_path)
        except OSError as exc:
            raise UserBridgeUnavailableError("bridge socket disappeared") from exc
        if (current.st_dev, current.st_ino) != expected:
            raise UserBridgePeerError("bridge socket identity changed")
        if not stat.S_ISSOCK(current.st_mode) or current.st_uid != self.expected_server_uid or current.st_mode & 0o007:
            raise UserBridgePeerError("bridge socket metadata changed")

    @staticmethod
    def _validate_response(payload: bytes, request_id: str, method: str) -> dict[str, Any]:
        try:
            response = _json_loads(payload, max_bytes=MAX_RESPONSE_BYTES, too_large_code="response_too_large")
        except UserBridgeProtocolError as exc:
            raise UserBridgeResponseError(str(exc)) from exc
        if not isinstance(response, dict):
            raise UserBridgeResponseError("response is not an object")
        if response.get("protocol") != BRIDGE_PROTOCOL or response.get("request_id") != request_id:
            raise UserBridgeResponseError("response binding is invalid")
        status = response.get("status")
        if status == "ok":
            if set(response) != {"protocol", "request_id", "method", "status", "projection"}:
                raise UserBridgeResponseError("response fields are invalid")
            if response.get("method") != method or not isinstance(response.get("projection"), dict):
                raise UserBridgeResponseError("response projection is invalid")
            return response
        if status == "error":
            if set(response) != {"protocol", "request_id", "status", "error"}:
                raise UserBridgeResponseError("response fields are invalid")
            error = response.get("error")
            if not isinstance(error, dict) or set(error) != {"code", "message"}:
                raise UserBridgeResponseError("response error is invalid")
            if _safe_string(error.get("code"), code=True) is None or _safe_string(error.get("message"), code=True) is None:
                raise UserBridgeResponseError("response error is invalid")
            return response
        raise UserBridgeResponseError("response status is invalid")

def _read_line(
    connection: socket.socket,
    *,
    limit: int = MAX_REQUEST_BYTES,
    too_large_code: str = "request_too_large",
) -> bytes:
    chunks: list[bytes] = []
    size = 0
    terminated = False
    while True:
        chunk = connection.recv(4096)
        if not chunk:
            break
        newline = chunk.find(b"\n")
        if newline >= 0:
            if chunk[newline + 1:]:
                raise UserBridgeProtocolError("trailing_data")
            chunk = chunk[:newline]
            chunks.append(chunk)
            size += len(chunk)
            terminated = True
            break
        chunks.append(chunk)
        size += len(chunk)
        if size > limit:
            raise UserBridgeProtocolError(too_large_code)
    if not terminated or size == 0:
        raise UserBridgeProtocolError("invalid_request")
    return b"".join(chunks)


def _configured_uid(raw: str | None) -> int:
    value = raw if raw is not None else os.environ.get("OVERSEER_BRIDGE_PEER_UID", str(DEFAULT_OVERSEER_UID))
    try:
        uid = int(value, 10)
    except (TypeError, ValueError) as exc:
        raise UserBridgeProtocolError("peer uid must be numeric") from exc
    if uid < 0:
        raise UserBridgeProtocolError("peer uid must be nonnegative")
    return uid


def create_default_bridge(*, allowed_peer_uid: int) -> UserBridge:
    """Construct the production bridge with fixed, read-only user providers."""

    from .user_bridge_providers import CodexSessionProjectionProvider, CodexUsageProjectionProvider

    return UserBridge(
        allowed_peer_uid=allowed_peer_uid,
        sessions_provider=CodexSessionProjectionProvider(),
        usage_provider=CodexUsageProjectionProvider(),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="serve the read-only Overseer user bridge")
    subparsers = parser.add_subparsers(dest="command", required=True)
    serve = subparsers.add_parser("serve")
    serve.add_argument("--socket-fd", type=int, default=3)
    serve.add_argument("--peer-uid")
    args = parser.parse_args(argv)
    if args.command != "serve":
        parser.error("unsupported command")
    if args.socket_fd < 0:
        parser.error("socket fd must be nonnegative")
    try:
        listener = socket.fromfd(args.socket_fd, socket.AF_UNIX, socket.SOCK_STREAM)
        bridge = create_default_bridge(allowed_peer_uid=_configured_uid(args.peer_uid))
        bridge.serve_forever(listener)
    except UserBridgeProtocolError as exc:
        parser.error(str(exc))
    finally:
        if "listener" in locals():
            listener.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
