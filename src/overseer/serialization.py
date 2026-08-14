"""JSON serialization helpers for Overseer dataclasses and enums."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import fields, is_dataclass
from enum import Enum
from types import UnionType
from typing import Any, TypeVar, Union, get_args, get_origin, get_type_hints

T = TypeVar("T")


# These omissions are a wire-compatibility rule for the two admin dataclasses
# only.  Keeping the type key explicit prevents an unrelated dataclass that
# happens to use an ``environment`` or ``adapter_metadata`` field from being
# silently rewritten.
_LEGACY_DEFAULT_OMISSIONS: dict[str, frozenset[str]] = {
    "overseer.admin.AdminCommandStep": frozenset({"environment", "clear_environment"}),
    "overseer.admin.AdminChangePlan": frozenset({"adapter_metadata"}),
}


def to_jsonable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, frozenset):
        return sorted(to_jsonable(item) for item in value)
    if isinstance(value, tuple):
        return [to_jsonable(item) for item in value]
    if isinstance(value, list):
        return [to_jsonable(item) for item in value]
    if isinstance(value, Mapping):
        return {str(key): to_jsonable(item) for key, item in value.items()}
    if is_dataclass(value):
        omission_fields = _LEGACY_DEFAULT_OMISSIONS.get(
            f"{type(value).__module__}.{type(value).__qualname__}",
            frozenset(),
        )
        payload = {}
        for field in fields(value):
            field_value = getattr(value, field.name)
            # These fields were added to AdminCommandStep after legacy plan
            # payloads were already persisted.  Omit their defaults so an
            # empty environment does not change strict source digests or
            # migration comparisons; non-empty values remain explicit.
            if field.name in omission_fields and field.name == "environment" and field_value == ():
                continue
            if field.name in omission_fields and field.name == "clear_environment" and field_value is False:
                continue
            if field.name in omission_fields and field.name == "adapter_metadata" and field_value == {}:
                continue
            payload[field.name] = to_jsonable(field_value)
        return payload
    return value


def dataclass_from_jsonable(cls: type[T], data: dict[str, Any]) -> T:
    values: dict[str, Any] = {}
    type_hints = get_type_hints(cls)
    for field in fields(cls):
        if field.name not in data:
            continue
        values[field.name] = _coerce_value(type_hints.get(field.name, field.type), data[field.name])
    return cls(**values)


def _coerce_value(target_type: Any, value: Any) -> Any:
    origin = get_origin(target_type)
    args = get_args(target_type)

    if value is None:
        return None

    if origin in (Union, UnionType):
        for subtype in args:
            if subtype is type(None):
                continue
            try:
                return _coerce_value(subtype, value)
            except (TypeError, ValueError):
                continue
        return value

    if origin is frozenset:
        subtype = args[0] if args else Any
        return frozenset(_coerce_value(subtype, item) for item in value)

    if origin is tuple:
        subtype = args[0] if args else Any
        return tuple(_coerce_value(subtype, item) for item in value)

    if origin is Mapping:
        key_type, value_type = args if len(args) == 2 else (Any, Any)
        return {
            _coerce_value(key_type, key): _coerce_value(value_type, item)
            for key, item in value.items()
        }

    if isinstance(target_type, type) and issubclass(target_type, Enum):
        return target_type(value)

    if isinstance(target_type, type) and is_dataclass(target_type):
        return dataclass_from_jsonable(target_type, value)

    return value
