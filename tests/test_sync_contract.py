import json

import pytest

from angr_mcp_plugin.sync_contract import (
    SCHEMA_VERSION,
    SyncProgram,
    SyncSnapshot,
    from_json,
    to_json,
    validate_snapshot_dict,
)


def test_sync_roundtrip():
    snapshot = SyncSnapshot(
        schema_version=SCHEMA_VERSION,
        program=SyncProgram(name="a.out", path="/tmp/a.out", architecture="AMD64", entry=0x401000),
        generated_at_unix=123456,
        functions=[{"address": "0x401000", "name": "main"}],
        strings=[{"address": "0x402000", "value": "hello"}],
        comments=[],
        metadata={"source": "test"},
    )
    encoded = to_json(snapshot)
    decoded = from_json(encoded)
    assert decoded.schema_version == SCHEMA_VERSION
    assert decoded.program.name == "a.out"
    assert decoded.functions[0]["name"] == "main"


def test_sync_validation_missing_keys():
    with pytest.raises(ValueError):
        validate_snapshot_dict({"schema_version": SCHEMA_VERSION})


def test_sync_validation_wrong_schema():
    payload = {
        "schema_version": "0.9",
        "program": {},
        "generated_at_unix": 0,
        "functions": [],
        "strings": [],
        "comments": [],
        "metadata": {},
    }
    with pytest.raises(ValueError):
        from_json(json.dumps(payload))
