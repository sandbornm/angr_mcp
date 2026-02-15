"""Automation and sync-oriented tools."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from ..session_state import SessionState
from ..sync_contract import SCHEMA_VERSION, SyncProgram, SyncSnapshot, from_json, save_file, to_json


def _function_rows(project: Any) -> list[dict[str, Any]]:
    functions = getattr(getattr(project, "kb", None), "functions", None)
    if functions is None or not hasattr(functions, "items"):
        return []
    rows: list[dict[str, Any]] = []
    for addr, func in sorted(functions.items(), key=lambda item: int(item[0])):
        rows.append(
            {
                "address": f"0x{addr:x}",
                "name": getattr(func, "name", None),
                "size": getattr(func, "size", None),
            }
        )
    return rows


def _string_rows(project: Any) -> list[dict[str, Any]]:
    strings = getattr(getattr(project, "kb", None), "strings", None)
    if strings is None:
        return []
    items = list(strings.items()) if hasattr(strings, "items") else list(strings)
    if items and isinstance(items[0], tuple):
        items = sorted(items, key=lambda item: int(item[0]) if isinstance(item[0], int) else -1)
    out: list[dict[str, Any]] = []
    for item in items:
        if isinstance(item, tuple) and len(item) == 2:
            addr, value = item
        else:
            addr = getattr(item, "addr", None)
            value = getattr(item, "string", None) or str(item)
        out.append({"address": f"0x{int(addr):x}" if isinstance(addr, int) else None, "value": str(value)})
    return out


def register_automation_tools(mcp: Any, session_state: SessionState) -> None:
    @mcp.tool()
    def am_sync_export(output_path: str | None = None) -> dict[str, Any]:
        """Export deterministic snapshot of active analysis state."""
        project = session_state.require_project()
        descriptor = session_state.get_program_descriptor()
        snapshot = SyncSnapshot(
            schema_version=SCHEMA_VERSION,
            program=SyncProgram(
                name=descriptor.name,
                path=descriptor.path,
                architecture=descriptor.architecture,
                entry=descriptor.entry,
            ),
            generated_at_unix=int(time.time()),
            functions=_function_rows(project),
            strings=_string_rows(project),
            comments=[],
            metadata={"tool": "angr_mcp", "mode": "plugin_bound"},
        )
        payload = to_json(snapshot)
        if output_path:
            save_file(output_path, snapshot)
        return {"snapshot": payload, "output_path": output_path}

    @mcp.tool()
    def am_sync_import(
        snapshot_json: str | None = None,
        snapshot_path: str | None = None,
        apply_changes: bool = True,
    ) -> dict[str, Any]:
        """
        Validate and ingest a snapshot contract.

        When apply_changes is true, function names/comments are applied to the active
        project when present in the snapshot.
        """
        if not snapshot_json and not snapshot_path:
            raise ValueError("Either snapshot_json or snapshot_path must be provided")
        if snapshot_path:
            payload = Path(snapshot_path).read_text(encoding="utf-8")
        else:
            payload = snapshot_json or ""
        parsed = from_json(payload)
        applied = {"renamed_functions": 0, "applied_comments": 0}
        apply_errors: list[str] = []
        if apply_changes:
            try:
                project = session_state.require_project()
                kb = getattr(project, "kb", None)
                functions = getattr(kb, "functions", None)
                comments = getattr(kb, "comments", None)
                for entry in parsed.functions:
                    addr_text = entry.get("address")
                    new_name = entry.get("name")
                    if not addr_text or not new_name or not isinstance(addr_text, str):
                        continue
                    try:
                        addr = int(addr_text, 16)
                    except ValueError:
                        continue
                    if functions is not None and addr in functions:
                        func = functions[addr]
                        if getattr(func, "name", None) != new_name:
                            try:
                                func.name = new_name
                                applied["renamed_functions"] += 1
                            except Exception as exc:  # noqa: BLE001
                                apply_errors.append(f"rename {addr_text}: {exc}")
                for entry in parsed.comments:
                    addr_text = entry.get("address")
                    text = entry.get("text")
                    if comments is None or not addr_text or not isinstance(addr_text, str):
                        continue
                    try:
                        addr = int(addr_text, 16)
                    except ValueError:
                        continue
                    try:
                        comments[addr] = text
                        applied["applied_comments"] += 1
                    except Exception as exc:  # noqa: BLE001
                        apply_errors.append(f"comment {addr_text}: {exc}")
                session_state.refresh_gui()
            except Exception as exc:  # noqa: BLE001
                apply_errors.append(str(exc))

        return {
            "schema_version": parsed.schema_version,
            "program": {
                "name": parsed.program.name,
                "path": parsed.program.path,
                "architecture": parsed.program.architecture,
                "entry": parsed.program.entry,
            },
            "counts": {
                "functions": len(parsed.functions),
                "strings": len(parsed.strings),
                "comments": len(parsed.comments),
            },
            "applied": applied,
            "apply_changes": apply_changes,
            "apply_errors": apply_errors,
        }

    @mcp.tool()
    def am_run_batch(actions: list[dict[str, Any]]) -> dict[str, Any]:
        """Run deterministic non-interactive operation batches."""
        if not isinstance(actions, list):
            raise ValueError("actions must be a list")

        results: list[dict[str, Any]] = []
        for index, action in enumerate(actions):
            action_type = action.get("type")
            try:
                if action_type == "sync_export":
                    result = am_sync_export(output_path=action.get("output_path"))
                elif action_type == "sync_import":
                    result = am_sync_import(
                        snapshot_json=action.get("snapshot_json"),
                        snapshot_path=action.get("snapshot_path"),
                        apply_changes=bool(action.get("apply_changes", True)),
                    )
                elif action_type == "current_program":
                    descriptor = session_state.get_program_descriptor()
                    result = {
                        "name": descriptor.name,
                        "path": descriptor.path,
                        "architecture": descriptor.architecture,
                        "entry": descriptor.entry,
                    }
                else:
                    raise ValueError(f"Unsupported batch action type: {action_type}")
                results.append({"index": index, "ok": True, "type": action_type, "result": result})
            except Exception as exc:  # noqa: BLE001 - structured batch continuation
                results.append({"index": index, "ok": False, "type": action_type, "error": str(exc)})

        return {
            "results": results,
            "total": len(results),
            "failed": sum(1 for row in results if not row["ok"]),
        }

