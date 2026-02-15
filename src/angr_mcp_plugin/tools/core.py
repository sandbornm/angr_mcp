"""Core GUI-bound angr MCP tools."""

from __future__ import annotations

from typing import Any

from ..session_state import SessionState


def _function_to_row(addr: int, func: Any) -> dict[str, Any]:
    return {
        "address": f"0x{addr:x}",
        "name": getattr(func, "name", None),
        "size": getattr(func, "size", None),
        "is_plt": bool(getattr(func, "is_plt", False)),
        "is_syscall": bool(getattr(func, "is_syscall", False)),
    }


def register_core_tools(mcp: Any, session_state: SessionState) -> None:
    """Register the tool surface tied to active angr-management context."""

    @mcp.tool()
    def am_get_current_program(binary_path: str | None = None) -> dict[str, Any]:
        """Return descriptor for the program currently active in angr-management."""
        if binary_path:
            project = session_state.resolve_project(binary_path=binary_path)
            filename = getattr(project, "filename", None)
            loader = getattr(project, "loader", None)
            main_object = getattr(loader, "main_object", None) if loader is not None else None
            arch = getattr(project, "arch", None)
            entry = getattr(main_object, "entry", None)
            return {
                "name": str(getattr(main_object, "binary", filename)) if main_object is not None else str(filename),
                "path": str(filename) if filename is not None else None,
                "architecture": str(getattr(arch, "name", None)) if arch is not None else None,
                "entry": int(entry) if isinstance(entry, int) else None,
            }
        descriptor = session_state.get_program_descriptor()
        return {
            "name": descriptor.name,
            "path": descriptor.path,
            "architecture": descriptor.architecture,
            "entry": descriptor.entry,
        }

    @mcp.tool()
    def am_list_functions(offset: int = 0, limit: int = 100) -> dict[str, Any]:
        """List functions from active project's knowledge base."""
        project = session_state.require_project()
        if limit < 0:
            raise ValueError("limit must be >= 0")
        if offset < 0:
            raise ValueError("offset must be >= 0")
        functions = getattr(getattr(project, "kb", None), "functions", None)
        if functions is None:
            return {"functions": [], "total": 0}
        items: list[dict[str, Any]] = []
        all_pairs = list(functions.items()) if hasattr(functions, "items") else []
        for addr, func in all_pairs[offset : offset + limit]:
            items.append(_function_to_row(addr, func))
        return {"functions": items, "total": len(all_pairs), "offset": offset, "limit": limit}

    @mcp.tool()
    def am_get_function(address: str) -> dict[str, Any]:
        """Get details for a function by address."""
        project = session_state.require_project()
        addr = int(address, 16)
        functions = getattr(getattr(project, "kb", None), "functions", None)
        if functions is None or addr not in functions:
            return {"error": f"Function not found at {address}"}
        func = functions[addr]
        return _function_to_row(addr, func)

    @mcp.tool()
    def am_decompile_function(address: str) -> dict[str, Any]:
        """
        Attempt to decompile a function.

        Requires angr decompiler support in the active environment.
        """
        project = session_state.require_project()
        addr = int(address, 16)
        try:
            result = project.analyses.Decompiler(addr)
            codegen = getattr(result, "codegen", None)
            text = str(getattr(codegen, "text", "")) if codegen is not None else ""
            return {"address": address, "decompilation": text}
        except Exception as exc:  # noqa: BLE001
            return {
                "address": address,
                "error": str(exc),
                "note": "Decompiler may require additional analyses/plugins for this binary.",
            }

    @mcp.tool()
    def am_list_strings(offset: int = 0, limit: int = 200) -> dict[str, Any]:
        """List known strings from the active project."""
        project = session_state.require_project()
        if limit < 0:
            raise ValueError("limit must be >= 0")
        if offset < 0:
            raise ValueError("offset must be >= 0")
        kb = getattr(project, "kb", None)
        strings = getattr(kb, "strings", None)
        if strings is None:
            return {"strings": [], "total": 0}
        rows: list[dict[str, Any]] = []
        iterable = list(strings.items()) if hasattr(strings, "items") else list(strings)
        for entry in iterable[offset : offset + limit]:
            if isinstance(entry, tuple) and len(entry) == 2:
                addr, value = entry
            else:
                addr = getattr(entry, "addr", None)
                value = getattr(entry, "string", None) or str(entry)
            rows.append({"address": f"0x{int(addr):x}" if isinstance(addr, int) else None, "value": str(value)})
        return {"strings": rows, "total": len(iterable), "offset": offset, "limit": limit}

    @mcp.tool()
    def am_get_xrefs_to(address: str, offset: int = 0, limit: int = 100) -> dict[str, Any]:
        """List xrefs-to for a target address when available in KB."""
        project = session_state.require_project()
        addr = int(address, 16)
        xrefs = getattr(getattr(project, "kb", None), "xrefs", None)
        if xrefs is None or not hasattr(xrefs, "get_xrefs_by_dst"):
            return {"xrefs": [], "total": 0, "note": "xrefs API unavailable in current project context"}
        refs = list(xrefs.get_xrefs_by_dst(addr))
        rows = refs[offset : offset + limit]
        return {
            "xrefs": [
                {
                    "src": f"0x{int(getattr(ref, 'ins_addr', 0)):x}",
                    "dst": f"0x{int(getattr(ref, 'dst', addr)):x}",
                    "type": str(getattr(ref, "type", "")),
                }
                for ref in rows
            ],
            "total": len(refs),
            "offset": offset,
            "limit": limit,
        }

    @mcp.tool()
    def am_rename_function(address: str, new_name: str) -> dict[str, Any]:
        """Rename a function at address and request GUI refresh."""
        if not new_name or not new_name.strip():
            raise ValueError("new_name must be a non-empty string")
        project = session_state.require_project()
        addr = int(address, 16)
        functions = getattr(getattr(project, "kb", None), "functions", None)
        if functions is None or addr not in functions:
            return {"error": f"Function not found at {address}"}
        func = functions[addr]
        old_name = getattr(func, "name", None)
        try:
            func.name = new_name
        except Exception as exc:  # noqa: BLE001
            return {"error": f"Failed to rename function: {exc}"}
        refresh = session_state.refresh_gui()
        return {
            "address": address,
            "old_name": old_name,
            "new_name": new_name,
            "refresh": refresh,
        }

    @mcp.tool()
    def am_set_comment(address: str, comment: str) -> dict[str, Any]:
        """Set comment text at an address in KB comments and request GUI refresh."""
        project = session_state.require_project()
        addr = int(address, 16)
        kb = getattr(project, "kb", None)
        comments = getattr(kb, "comments", None)
        if comments is None:
            return {"error": "Comments API unavailable on this angr project context"}
        old_value = comments.get(addr) if hasattr(comments, "get") else None
        try:
            comments[addr] = comment
        except Exception as exc:  # noqa: BLE001
            return {"error": f"Failed to set comment: {exc}"}
        refresh = session_state.refresh_gui()
        return {
            "address": address,
            "old_comment": old_value,
            "new_comment": comment,
            "refresh": refresh,
        }

