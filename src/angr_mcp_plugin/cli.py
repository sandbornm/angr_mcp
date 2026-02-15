"""CLI helpers for development and contract validation."""

from __future__ import annotations

import argparse
import json
import time
from dataclasses import asdict
from pathlib import Path

from .mcp_server import AngrEmbeddedMCPServer, ServerConfig
from .session_state import ProgramDescriptor, SessionState
from .sync_contract import SCHEMA_VERSION, SyncProgram, SyncSnapshot, from_json


def run_dev_server() -> None:
    parser = argparse.ArgumentParser(description="Run angr MCP plugin server in development mode.")
    parser.add_argument("--transport", default="streamable-http")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8766)
    args = parser.parse_args()

    state = SessionState()
    # Bind placeholder descriptor for clean responses when not attached to GUI.
    state.set_project(
        type(
            "_DevProject",
            (),
            {
                "filename": "dev-placeholder.bin",
                "loader": type("_Loader", (), {"main_object": type("_Obj", (), {"entry": 0x401000, "binary": "dev"})()}),
                "arch": type("_Arch", (), {"name": "amd64"})(),
                "kb": type("_Kb", (), {"functions": {}, "strings": {}})(),
            },
        )()
    )
    server = AngrEmbeddedMCPServer(
        state,
        config=ServerConfig(transport=args.transport, host=args.host, port=args.port),
    )
    result = server.start()
    print(json.dumps(result, indent=2))
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(json.dumps(server.stop(), indent=2))


def validate_sync_contract_file() -> None:
    parser = argparse.ArgumentParser(description="Validate an angr MCP sync snapshot.")
    parser.add_argument("path", help="Path to snapshot JSON file")
    args = parser.parse_args()
    parsed = from_json(Path(args.path).read_text(encoding="utf-8"))
    print(
        json.dumps(
            {
                "valid": True,
                "schema_version": parsed.schema_version,
                "program": asdict(parsed.program),
                "counts": {
                    "functions": len(parsed.functions),
                    "strings": len(parsed.strings),
                    "comments": len(parsed.comments),
                },
            },
            indent=2,
            sort_keys=True,
        )
    )


def _make_empty_snapshot() -> SyncSnapshot:
    return SyncSnapshot(
        schema_version=SCHEMA_VERSION,
        program=SyncProgram(**asdict(ProgramDescriptor(name=None, path=None, architecture=None, entry=None))),
        generated_at_unix=int(time.time()),
        functions=[],
        strings=[],
        comments=[],
        metadata={},
    )

