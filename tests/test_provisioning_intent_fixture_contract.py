"""Focused contract tests for the canonical typed provisioning-intent fixture."""
from __future__ import annotations

from collections import OrderedDict
import json
from pathlib import Path
import re

import pytest

from overseer.provisioning_bundle import (
    INTENT_FIELDS,
    INTENT_KIND,
    INTENT_SCHEMA_VERSION,
    _COMMIT,
    _INTENT_FIELD_ORDER,
    parse_provisioning_intent,
)


FIXTURE = Path(__file__).parent / "fixtures" / "provisioning_intent_v1.json"
EXPECTED_FIELDS = (
    "schema_version",
    "request_id",
    "plan_id",
    "kind",
    "project_id",
    "resource_id",
    "root_id",
    "policy_revision",
    "source_commit",
    "requested_by",
    "reason",
    "supersedes_plan_id",
)


def _load_fixture() -> OrderedDict[str, object]:
    with FIXTURE.open(encoding="utf-8") as stream:
        return json.load(stream, object_pairs_hook=OrderedDict)


def test_fixture_declares_exact_ordered_schema_and_one_valid_example():
    fixture = _load_fixture()

    assert list(fixture) == ["$schema", "type", "additionalProperties", "properties", "required", "examples"]
    assert fixture["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert fixture["type"] == "object"
    assert fixture["additionalProperties"] is False
    properties = fixture["properties"]
    assert isinstance(properties, OrderedDict)
    assert tuple(properties) == EXPECTED_FIELDS
    assert all(properties[field]["type"] == "string" for field in EXPECTED_FIELDS)
    assert fixture["required"] == list(EXPECTED_FIELDS)
    assert isinstance(fixture["examples"], list)
    assert len(fixture["examples"]) == 1
    example = fixture["examples"][0]
    assert isinstance(example, OrderedDict)
    assert tuple(example) == EXPECTED_FIELDS
    assert all(isinstance(value, str) for value in example.values())
    assert set(example) == set(EXPECTED_FIELDS)


def test_fixture_constants_and_validation_boundary_match_real_source():
    fixture = _load_fixture()
    properties = fixture["properties"]
    example = fixture["examples"][0]

    assert tuple(_INTENT_FIELD_ORDER) == EXPECTED_FIELDS
    assert set(INTENT_FIELDS) == set(EXPECTED_FIELDS)
    assert fixture["properties"]["schema_version"]["const"] == INTENT_SCHEMA_VERSION
    assert fixture["properties"]["kind"]["const"] == INTENT_KIND
    assert fixture["properties"]["source_commit"]["pattern"] == _COMMIT.pattern
    assert properties["schema_version"] == {
        "type": "string",
        "const": INTENT_SCHEMA_VERSION,
    }
    assert properties["kind"] == {"type": "string", "const": INTENT_KIND}
    assert properties["source_commit"] == {
        "type": "string",
        "pattern": re.compile(r"[0-9a-f]{40}\Z").pattern,
    }
    assert properties["supersedes_plan_id"] == {
        "type": "string",
        "pattern": r"(?:^$|^\S(?:.*\S)?$)",
    }
    assert parse_provisioning_intent(example).source_commit == example["source_commit"]

    for field in EXPECTED_FIELDS[:-1]:
        with pytest.raises(ValueError):
            parse_provisioning_intent({**example, field: ""})
        with pytest.raises(ValueError):
            parse_provisioning_intent({**example, field: f" {example[field]}"})
        with pytest.raises(ValueError):
            parse_provisioning_intent({**example, field: f"{example[field]} "})
    with pytest.raises(ValueError):
        parse_provisioning_intent({**example, "schema_version": "2"})
    with pytest.raises(ValueError):
        parse_provisioning_intent({**example, "kind": "other"})
    for source_commit in ("A" * 40, "a" * 39, "a" * 41, "not-a-commit"):
        with pytest.raises(ValueError):
            parse_provisioning_intent({**example, "source_commit": source_commit})
    assert parse_provisioning_intent({**example, "supersedes_plan_id": ""}).supersedes_plan_id == ""
    with pytest.raises(ValueError):
        parse_provisioning_intent({**example, "supersedes_plan_id": " successor "})
    with pytest.raises(ValueError):
        parse_provisioning_intent({**example, "unexpected": "field"})
