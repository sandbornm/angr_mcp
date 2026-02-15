"""Versioned sync contract for export/import of angr analysis state."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1.0"


@dataclass(frozen=True)
class SyncProgram:
    name: str | None
    path: str | None
    architecture: str | None
    entry: int | None


@dataclass(frozen=True)
class SyncSnapshot:
    schema_version: str
    program: SyncProgram
    generated_at_unix: int
    functions: list[dict[str, Any]]
    strings: list[dict[str, Any]]
    comments: list[dict[str, Any]]
    metadata: dict[str, Any]


def to_json(snapshot: SyncSnapshot) -> str:
    """Serialize snapshot to deterministic JSON."""
    return json.dumps(asdict(snapshot), indent=2, sort_keys=True)


def from_json(payload: str) -> SyncSnapshot:
    """Parse and validate a sync snapshot JSON payload."""
    data = json.loads(payload)
    validate_snapshot_dict(data)
    program = SyncProgram(**data["program"])
    return SyncSnapshot(
        schema_version=data["schema_version"],
        program=program,
        generated_at_unix=data["generated_at_unix"],
        functions=data["functions"],
        strings=data["strings"],
        comments=data["comments"],
        metadata=data["metadata"],
    )


def load_file(path: str | Path) -> SyncSnapshot:
    return from_json(Path(path).read_text(encoding="utf-8"))


def save_file(path: str | Path, snapshot: SyncSnapshot) -> None:
    Path(path).write_text(to_json(snapshot), encoding="utf-8")


def validate_snapshot_dict(data: dict[str, Any]) -> None:
    required_keys = {
        "schema_version",
        "program",
        "generated_at_unix",
        "functions",
        "strings",
        "comments",
        "metadata",
    }
    missing = sorted(required_keys.difference(data.keys()))
    if missing:
        raise ValueError(f"Missing sync snapshot keys: {missing}")
    if data["schema_version"] != SCHEMA_VERSION:
        raise ValueError(f"Unsupported schema_version={data['schema_version']!r}; expected {SCHEMA_VERSION!r}")
    if not isinstance(data["program"], dict):
        raise ValueError("program must be an object")
    if not isinstance(data["functions"], list):
        raise ValueError("functions must be an array")
    if not isinstance(data["strings"], list):
        raise ValueError("strings must be an array")
    if not isinstance(data["comments"], list):
        raise ValueError("comments must be an array")
    if not isinstance(data["metadata"], dict):
        raise ValueError("metadata must be an object")
    if not isinstance(data["generated_at_unix"], int):
        raise ValueError("generated_at_unix must be an integer")
