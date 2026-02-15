"""Embedded MCP server host for angr-management plugin runtime."""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from typing import Any

from mcp.server.fastmcp import FastMCP

from .session_state import SessionState
from .tools import register_automation_tools, register_core_tools, register_symbolic_tools

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ServerConfig:
    transport: str = "streamable-http"
    host: str = "127.0.0.1"
    port: int = 8766


class AngrEmbeddedMCPServer:
    """Owns FastMCP instance and optional background server thread."""

    def __init__(self, session_state: SessionState, config: ServerConfig | None = None) -> None:
        self.session_state = session_state
        self.config = config or ServerConfig()
        self.mcp = FastMCP("angr-mcp-plugin")
        self._thread: threading.Thread | None = None
        self._started = False
        self._register_tools()

    def _register_tools(self) -> None:
        register_core_tools(self.mcp, self.session_state)
        register_symbolic_tools(self.mcp, self.session_state)
        register_automation_tools(self.mcp, self.session_state)

    def start(self) -> dict[str, Any]:
        if self._started:
            return {"status": "already_running", "transport": self.config.transport, "port": self.config.port}

        if self.config.transport == "stdio":
            raise ValueError("stdio transport cannot be embedded in angr-management plugin host")

        # FastMCP 1.x configures network bind via settings, not run() kwargs.
        self.mcp.settings.host = self.config.host
        self.mcp.settings.port = self.config.port

        def _run_server() -> None:
            try:
                self.mcp.run(transport=self.config.transport)
            except Exception:  # noqa: BLE001 - log and propagate to thread boundary
                logger.exception("Embedded MCP server exited with an error")

        self._thread = threading.Thread(target=_run_server, name="angr-mcp-server", daemon=True)
        self._thread.start()
        self._started = True
        return {
            "status": "started",
            "transport": self.config.transport,
            "host": self.config.host,
            "port": self.config.port,
        }

    def stop(self) -> dict[str, Any]:
        # FastMCP does not currently expose a uniform stop() API for all transports.
        # We keep a structured return and mark host state as stopped for plugin lifecycle.
        self._started = False
        return {
            "status": "stopped",
            "note": "Transport shutdown is cooperative; restart angr-management process for hard stop.",
        }

