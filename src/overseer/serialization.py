"""JSON serialization helpers for Overseer dataclasses and enums."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import fields, is_dataclass
from enum import Enum
from typing import Any, TypeVar, get_args, get_origin, get_type_hints

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
    if isinstance(value, Mapping):
        return {str(key): to_jsonable(item) for key, item in value.items()}
    if is_dataclass(value):
        return {field.name: to_jsonable(getattr(value, field.name)) for field in fields(value)}
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
