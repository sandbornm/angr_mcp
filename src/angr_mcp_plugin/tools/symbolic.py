"""Symbolic execution helpers bound to active angr project."""

from __future__ import annotations

import signal
from contextlib import contextmanager
from typing import Any

from ..session_state import SessionState


@contextmanager
def _timeout(seconds: int):
    if seconds <= 0:
        yield
        return

    def _handler(signum, frame):  # type: ignore[no-untyped-def]
        raise TimeoutError(f"Operation timed out after {seconds} seconds")

    previous = signal.signal(signal.SIGALRM, _handler)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def register_symbolic_tools(mcp: Any, session_state: SessionState) -> None:
    @mcp.tool()
    def am_angr_entry(binary_path: str | None = None) -> dict[str, Any]:
        """Return entry-point metadata for active project."""
        project = session_state.resolve_project(binary_path=binary_path)
        loader = getattr(project, "loader", None)
        main_object = getattr(loader, "main_object", None) if loader is not None else None
        entry = getattr(main_object, "entry", None)
        return {"entry": f"0x{entry:x}" if isinstance(entry, int) else None}

    @mcp.tool()
    def am_angr_cfg(timeout: int = 60, binary_path: str | None = None) -> dict[str, Any]:
        """Build a CFG via CFGFast and summarize size."""
        project = session_state.resolve_project(binary_path=binary_path)
        with _timeout(timeout):
            cfg = project.analyses.CFGFast(normalize=True)
        graph = getattr(cfg, "graph", None)
        node_count = int(graph.number_of_nodes()) if graph is not None else 0
        edge_count = int(graph.number_of_edges()) if graph is not None else 0
        return {"nodes": node_count, "edges": edge_count}

    @mcp.tool()
    def am_angr_explore(
        find_addr: str,
        avoid_addrs: list[str] | None = None,
        timeout: int = 120,
        stdin_symbolic: bool = True,
        binary_path: str | None = None,
    ) -> dict[str, Any]:
        """Use simulation manager to find path reaching target address."""
        project = session_state.resolve_project(binary_path=binary_path)
        claripy = __import__("claripy")

        target = int(find_addr, 16)
        avoid = [int(a, 16) for a in (avoid_addrs or [])]

        if stdin_symbolic:
            sym_stdin = claripy.BVS("stdin", 8 * 128)
            state = project.factory.full_init_state(stdin=sym_stdin)
        else:
            state = project.factory.full_init_state()

        simgr = project.factory.simgr(state)
        with _timeout(timeout):
            simgr.explore(find=target, avoid=avoid)

        found = len(simgr.found) > 0
        result: dict[str, Any] = {
            "found": found,
            "active_states": len(simgr.active),
            "deadended_states": len(simgr.deadended),
        }
        if found:
            solved = simgr.found[0]
            stdin_stream = solved.posix.dumps(0)
            result["stdin_solution"] = stdin_stream.hex()
            result["stdin_solution_utf8"] = stdin_stream.decode("utf-8", errors="replace")
        return result
