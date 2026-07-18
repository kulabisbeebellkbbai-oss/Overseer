"""JSON serialization helpers for Overseer dataclasses and enums."""

from __future__ import annotations

from dataclasses import asdict, fields, is_dataclass
from enum import Enum
from typing import Any, TypeVar, get_args, get_origin

T = TypeVar("T")


def to_jsonable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, frozenset):
        return sorted(to_jsonable(item) for item in value)
    if isinstance(value, tuple):
        return [to_jsonable(item) for item in value]
    if isinstance(value, list):
        return [to_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {str(key): to_jsonable(item) for key, item in value.items()}
    if is_dataclass(value):
        return to_jsonable(asdict(value))
    return value


def dataclass_from_jsonable(cls: type[T], data: dict[str, Any]) -> T:
    values: dict[str, Any] = {}
    for field in fields(cls):
        if field.name not in data:
            continue
        values[field.name] = _coerce_value(field.type, data[field.name])
    return cls(**values)


def _coerce_value(target_type: Any, value: Any) -> Any:
    origin = get_origin(target_type)
    args = get_args(target_type)

    if value is None:
        return None

    if origin is frozenset:
        subtype = args[0] if args else Any
        return frozenset(_coerce_value(subtype, item) for item in value)

    if origin is tuple:
        subtype = args[0] if args else Any
        return tuple(_coerce_value(subtype, item) for item in value)

    if isinstance(target_type, type) and issubclass(target_type, Enum):
        return target_type(value)

    if isinstance(target_type, type) and is_dataclass(target_type):
        return dataclass_from_jsonable(target_type, value)

    return value
