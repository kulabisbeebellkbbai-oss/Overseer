"""Focused contract tests for the canonical typed provisioning-intent fixture."""
from __future__ import annotations

from collections import OrderedDict
import json
from pathlib import Path
import re
import shutil
import subprocess

import pytest

from overseer.provisioning_bundle import (
    INTENT_FIELDS,
    INTENT_KIND,
    INTENT_SCHEMA_VERSION,
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
    assert fixture["properties"]["source_commit"]["pattern"] == r"^[0-9a-f]{40}$"
    assert properties["schema_version"] == {
        "type": "string",
        "const": INTENT_SCHEMA_VERSION,
    }
    assert properties["kind"] == {"type": "string", "const": INTENT_KIND}
    assert properties["source_commit"] == {
        "type": "string",
        "pattern": r"^[0-9a-f]{40}$",
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
    valid_source_commit = "a" * 40
    source_commit_cases = (
        (valid_source_commit, True),
        ("A" * 40, False),
        ("a" * 39, False),
        ("a" * 41, False),
        ("x" + "a" * 39, False),
        ("a" * 39 + "x", False),
        ("a" * 40 + "\n", False),
        (" " + "a" * 40, False),
        ("a" * 40 + " ", False),
        ("not-a-commit", False),
    )
    source_commit_pattern = re.compile(properties["source_commit"]["pattern"])
    for source_commit, expected in source_commit_cases:
        parsed = True
        try:
            parse_provisioning_intent({**example, "source_commit": source_commit})
        except ValueError:
            parsed = False
        assert parsed is expected
        assert (source_commit_pattern.fullmatch(source_commit) is not None) is expected
    assert parse_provisioning_intent({**example, "supersedes_plan_id": ""}).supersedes_plan_id == ""
    with pytest.raises(ValueError):
        parse_provisioning_intent({**example, "supersedes_plan_id": " successor "})
    with pytest.raises(ValueError):
        parse_provisioning_intent({**example, "unexpected": "field"})


def test_fixture_patterns_are_ecmascript_compatible_and_preserve_json_schema_search_semantics():
    node = shutil.which("node") or shutil.which("nodejs")
    if node is None:
        pytest.skip("Node.js is unavailable")

    patterns = {
        field: properties["pattern"]
        for field, properties in _load_fixture()["properties"].items()
        if "pattern" in properties
    }
    script = r"""
const input = JSON.parse(require('fs').readFileSync(0, 'utf8'));
const regexes = Object.fromEntries(
  Object.entries(input.patterns).map(([field, pattern]) => [field, new RegExp(pattern)])
);
const samples = {
  request_id: [['request', true], ['', false], [' request', false], ['request ', false], ['\nrequest', false], ['request\n', false]],
  plan_id: [['plan', true], ['', false], [' plan', false], ['plan ', false], ['\nplan', false], ['plan\n', false]],
  project_id: [['project', true], ['', false], [' project', false], ['project ', false], ['\nproject', false], ['project\n', false]],
  resource_id: [['resource', true], ['', false], [' resource', false], ['resource ', false], ['\nresource', false], ['resource\n', false]],
  root_id: [['root', true], ['', false], [' root', false], ['root ', false], ['\nroot', false], ['root\n', false]],
  policy_revision: [['1', true], ['', false], [' 1', false], ['1 ', false], ['\n1', false], ['1\n', false]],
  requested_by: [['operator', true], ['', false], [' operator', false], ['operator ', false], ['\noperator', false], ['operator\n', false]],
  reason: [['reason', true], ['', false], [' reason', false], ['reason ', false], ['\nreason', false], ['reason\n', false]],
  source_commit: [['a'.repeat(40), true], ['A'.repeat(40), false], ['a'.repeat(39), false], ['a'.repeat(41), false], ['x' + 'a'.repeat(39), false], ['a'.repeat(39) + 'x', false], ['a'.repeat(40) + '\n', false], [' ' + 'a'.repeat(40), false], ['a'.repeat(40) + ' ', false]],
  supersedes_plan_id: [['', true], ['successor', true], [' successor', false], ['successor ', false], ['\nsuccessor', false], ['successor\n', false]],
};
for (const [field, cases] of Object.entries(samples)) {
  if (!(field in regexes)) throw new Error('missing pattern for ' + field);
  for (const [value, expected] of cases) {
    const actual = regexes[field].test(value);
    if (actual !== expected) throw new Error(field + ': ' + JSON.stringify(value) + ' expected ' + expected + ', got ' + actual);
  }
}
console.log(JSON.stringify({fields: Object.keys(regexes).length, validated: true}));
"""
    result = subprocess.run(
        [node, "-e", script],
        input=json.dumps({"patterns": patterns}),
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"fields": 10, "validated": True}
