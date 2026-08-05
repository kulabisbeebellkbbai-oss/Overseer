"""Operator CLI for the dedicated backup-provisioning control plane."""
from __future__ import annotations
import argparse
import fcntl
import json
import os
import stat
import time
from pathlib import Path
from .backup_provisioning import approve_plan_api, execute_plan_api, list_plans, stage_plan_api
from .backup_host_operations import ConcreteHostProvisioningAdapter
from .cli import dispatch_provisioning_review_outbox_status
from .provisioning_bundle import (
    ProvisioningBundleError,
    bundle_status,
    preflight_bundle_api,
    stage_bundle_api,
)

_MAX_BUNDLE_INTENT_BYTES = 64 * 1024
_MAX_BUNDLE_INTENT_SECONDS = 2.0
_REQUIRED_BUNDLE_INTENT_SEALS = (
    fcntl.F_SEAL_SEAL
    | fcntl.F_SEAL_SHRINK
    | fcntl.F_SEAL_GROW
    | fcntl.F_SEAL_WRITE
)


def _file_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
        info.st_uid, info.st_gid, info.st_size,
        info.st_mtime_ns, info.st_ctime_ns,
    )


def _read_bundle_intent(path: str) -> dict[str, object]:
    descriptor: int | None = None
    decoded: dict[str, object] | None = None
    invalid = False
    deadline = time.monotonic() + _MAX_BUNDLE_INTENT_SECONDS

    def require_time() -> None:
        if time.monotonic() > deadline:
            raise TimeoutError("bundle intent deadline expired")

    try:
        require_time()
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        )
        require_time()
        before = os.fstat(descriptor)
        require_time()
        entry = os.stat(path, follow_symlinks=False)
        require_time()
        if (
            not stat.S_ISREG(before.st_mode)
            or not stat.S_ISREG(entry.st_mode)
            or _file_identity(before) != _file_identity(entry)
            or before.st_size > _MAX_BUNDLE_INTENT_BYTES
        ):
            raise ValueError("invalid bundle intent file")
        chunks: list[bytes] = []
        offset = 0
        while offset < before.st_size:
            chunk = os.pread(descriptor, min(65536, before.st_size - offset), offset)
            require_time()
            if not chunk:
                raise ValueError("truncated bundle intent file")
            chunks.append(chunk)
            offset += len(chunk)
        extra = os.pread(descriptor, 1, offset)
        require_time()
        if extra:
            raise ValueError("growing bundle intent file")
        after = os.fstat(descriptor)
        require_time()
        final_entry = os.stat(path, follow_symlinks=False)
        require_time()
        if (
            _file_identity(after) != _file_identity(before)
            or _file_identity(final_entry) != _file_identity(before)
        ):
            raise ValueError("unstable bundle intent file")
        decoded_value = json.loads(b"".join(chunks).decode("utf-8"))
        require_time()
        if type(decoded_value) is not dict:
            raise ValueError("bundle intent must be a JSON object")
        decoded = decoded_value
    except Exception:
        invalid = True
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except Exception:
                invalid = True
            try:
                require_time()
            except Exception:
                invalid = True
    if invalid or decoded is None:
        raise ProvisioningBundleError("INVALID_BUNDLE_CLI_INPUT") from None
    return decoded


def _read_bundle_intent_fd(fd_number: int) -> dict[str, object]:
    descriptor: int | None = None
    decoded: dict[str, object] | None = None
    invalid = False
    deadline = time.monotonic() + _MAX_BUNDLE_INTENT_SECONDS

    def require_time() -> None:
        if time.monotonic() > deadline:
            raise TimeoutError("bundle intent deadline expired")

    try:
        descriptor = os.dup(fd_number)
        require_time()
        before = os.fstat(descriptor)
        require_time()
        before_seals = fcntl.fcntl(descriptor, fcntl.F_GET_SEALS)
        require_time()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 0
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size > _MAX_BUNDLE_INTENT_BYTES
            or before_seals != _REQUIRED_BUNDLE_INTENT_SEALS
        ):
            raise ValueError("invalid bundle intent descriptor")
        chunks: list[bytes] = []
        offset = 0
        while offset < before.st_size:
            chunk = os.pread(descriptor, min(65536, before.st_size - offset), offset)
            require_time()
            if not chunk or len(chunk) > before.st_size - offset:
                raise ValueError("truncated or growing bundle intent descriptor")
            chunks.append(chunk)
            offset += len(chunk)
        extra = os.pread(descriptor, 1, offset)
        require_time()
        if extra:
            raise ValueError("growing bundle intent descriptor")
        after = os.fstat(descriptor)
        require_time()
        after_seals = fcntl.fcntl(descriptor, fcntl.F_GET_SEALS)
        require_time()
        if (
            _file_identity(after) != _file_identity(before)
            or after_seals != _REQUIRED_BUNDLE_INTENT_SEALS
        ):
            raise ValueError("unstable bundle intent descriptor")
        decoded_value = json.loads(b"".join(chunks).decode("utf-8"))
        require_time()
        if type(decoded_value) is not dict:
            raise ValueError("bundle intent must be a JSON object")
        decoded = decoded_value
    except Exception:
        invalid = True
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except Exception:
                invalid = True
            try:
                require_time()
            except Exception:
                invalid = True
    if invalid or decoded is None:
        raise ProvisioningBundleError("INVALID_BUNDLE_CLI_INPUT") from None
    return decoded


def _parse_nonnegative_fd(value: str) -> int:
    try:
        fd_number = int(value, 10)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a nonnegative integer") from error
    if fd_number < 0:
        raise argparse.ArgumentTypeError("must be a nonnegative integer")
    return fd_number


def _write_bundle_cli_error(error_code: str) -> int:
    print(json.dumps(
        {
            "error": "provisioning_bundle_command_failed",
            "error_code": error_code,
            "ok": False,
        },
        sort_keys=True,
        separators=(",", ":"),
    ))
    return 2 if error_code in {
        "INVALID_BUNDLE_CLI_INPUT",
        "INVALID_BUNDLE_PREFLIGHT_REQUEST",
        "INVALID_BUNDLE_STAGE_REQUEST",
        "INVALID_BUNDLE_STATUS_REQUEST",
        "AUTHORITATIVE_REBUILD_MISMATCH",
        "INVALID_REVIEW_OUTBOX_REQUEST",
        "INVALID_REVIEW_OUTBOX_DISPATCH_REQUEST",
    } else 1


def _run_bundle_command(args: argparse.Namespace) -> int:
    try:
        if args.command == "bundle-preflight":
            intent = (
                _read_bundle_intent(args.intent_json)
                if args.intent_json is not None
                else _read_bundle_intent_fd(args.intent_fd)
            )
            result = preflight_bundle_api(
                args.store, {"intent": intent},
            )
        elif args.command == "bundle-stage":
            intent = (
                _read_bundle_intent(args.intent_json)
                if args.intent_json is not None
                else _read_bundle_intent_fd(args.intent_fd)
            )
            result = stage_bundle_api(
                args.store,
                {
                    "intent": intent,
                    "expected_preflight_digest": args.expected_preflight_digest,
                    "expected_bundle_digest": args.expected_bundle_digest,
                },
            )
        elif args.command == "bundle-status":
            result = bundle_status(args.store, args.plan_id)
        else:
            result = dispatch_provisioning_review_outbox_status(
                args.store,
                args.outbox_id,
                args.dispatched_by,
                args.dispatched_at,
            )
    except ProvisioningBundleError as error:
        code = str(error)
        allowed = {
            "INVALID_BUNDLE_CLI_INPUT",
            "INVALID_BUNDLE_PREFLIGHT_REQUEST",
            "INVALID_BUNDLE_STAGE_REQUEST",
            "INVALID_BUNDLE_STATUS_REQUEST",
            "AUTHORITATIVE_REBUILD_MISMATCH",
            "BUNDLE_PREFLIGHT_UNAVAILABLE",
            "BUNDLE_STAGE_UNAVAILABLE",
            "BUNDLE_NOT_FOUND",
            "BUNDLE_STATUS_INTEGRITY_ERROR",
            "BUNDLE_STATUS_UNAVAILABLE",
            "INVALID_REVIEW_OUTBOX_REQUEST",
            "INVALID_REVIEW_OUTBOX_DISPATCH_REQUEST",
            "REVIEW_OUTBOX_NOT_FOUND",
            "REVIEW_OUTBOX_INTEGRITY_ERROR",
            "REVIEW_OUTBOX_MESSAGE_MISMATCH",
            "REVIEW_DISPATCH_NOT_TERMINAL",
            "REVIEW_DISPATCH_INDETERMINATE",
            "REVIEW_DISPATCH_HOST_MUTATION",
            "REVIEW_DISPATCH_UNAVAILABLE",
        }
        if code not in allowed:
            code = {
                "bundle-preflight": "BUNDLE_PREFLIGHT_UNAVAILABLE",
                "bundle-stage": "BUNDLE_STAGE_UNAVAILABLE",
                "bundle-status": "BUNDLE_STATUS_UNAVAILABLE",
                "review-dispatch": "REVIEW_DISPATCH_UNAVAILABLE",
            }[args.command]
        return _write_bundle_cli_error(code)
    except Exception:
        return _write_bundle_cli_error({
            "bundle-preflight": "BUNDLE_PREFLIGHT_UNAVAILABLE",
            "bundle-stage": "BUNDLE_STAGE_UNAVAILABLE",
            "bundle-status": "BUNDLE_STATUS_UNAVAILABLE",
            "review-dispatch": "REVIEW_DISPATCH_UNAVAILABLE",
        }[args.command])
    print(json.dumps(result, sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="overseer-backup-provisioning")
    parser.add_argument("--store", required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    stage = commands.add_parser("stage")
    stage.add_argument("--plan-json", required=True)
    commands.add_parser("list")
    approve = commands.add_parser("approve")
    approve.add_argument("--plan-id", required=True)
    approve.add_argument("--approved-by", required=True)
    execute = commands.add_parser("execute")
    execute.add_argument("--plan-id", required=True)
    execute.add_argument("--privileged-confirmation", required=True)
    bundle_preflight = commands.add_parser("bundle-preflight")
    bundle_preflight_intent = bundle_preflight.add_mutually_exclusive_group(required=True)
    bundle_preflight_intent.add_argument("--intent-json")
    bundle_preflight_intent.add_argument("--intent-fd", type=_parse_nonnegative_fd)
    bundle_stage = commands.add_parser("bundle-stage")
    bundle_stage_intent = bundle_stage.add_mutually_exclusive_group(required=True)
    bundle_stage_intent.add_argument("--intent-json")
    bundle_stage_intent.add_argument("--intent-fd", type=_parse_nonnegative_fd)
    bundle_stage.add_argument("--expected-preflight-digest", required=True)
    bundle_stage.add_argument("--expected-bundle-digest", required=True)
    bundle_status_parser = commands.add_parser("bundle-status")
    bundle_status_parser.add_argument("--plan-id", required=True)
    review_dispatch = commands.add_parser("review-dispatch")
    review_dispatch.add_argument("--outbox-id", required=True)
    review_dispatch.add_argument("--dispatched-by", required=True)
    review_dispatch.add_argument("--dispatched-at")
    args = parser.parse_args(argv)
    if args.command == "stage":
        result = stage_plan_api(args.store, json.loads(Path(args.plan_json).read_text()))
    elif args.command == "list":
        result = list_plans(args.store)
    elif args.command == "approve":
        result = approve_plan_api(
            args.store,
            {"plan_id": args.plan_id, "approved_by": args.approved_by},
        )
    elif args.command == "execute":
        confirmation = args.privileged_confirmation
        result = execute_plan_api(
            args.store,
            {"plan_id": args.plan_id, "privileged_confirmation": confirmation},
            adapter_factory=lambda plan: ConcreteHostProvisioningAdapter(
                plan, privileged_confirmation=confirmation,
            ),
        )
    else:
        return _run_bundle_command(args)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
