"""angr-management plugin entrypoint hosting an embedded MCP server."""

from __future__ import annotations

import logging
import os
from typing import Any

from .mcp_server import AngrEmbeddedMCPServer, ServerConfig
from .session_state import SessionState

logger = logging.getLogger(__name__)

try:
    from angrmanagement.plugins import BasePlugin  # type: ignore
except Exception:  # noqa: BLE001 - keep test/dev mode functional without angr-management

    class BasePlugin:  # type: ignore[no-redef]
        """Fallback plugin base when angr-management is unavailable."""

        def __init__(self, workspace: Any | None = None) -> None:
            self.workspace = workspace


class AngrMCPPlugin(BasePlugin):
    """
    angr-management plugin that exposes current workspace via MCP.

    The plugin starts an embedded MCP server so external LLM MCP clients
    can call angr tools against the currently active angr-management program.
    """

    DISPLAY_NAME = "angr MCP Plugin"

    def __init__(self, workspace: Any | None = None) -> None:
        super().__init__(workspace)
        self._session_state = SessionState()
        if workspace is not None:
            self._session_state.bind_workspace(workspace)
        config = ServerConfig(
            transport=os.getenv("ANGR_MCP_TRANSPORT", "streamable-http"),  # type: ignore[arg-type]
            host=os.getenv("ANGR_MCP_HOST", "127.0.0.1"),
            port=int(os.getenv("ANGR_MCP_PORT", "8766")),
        )
        self._server = AngrEmbeddedMCPServer(self._session_state, config=config)
        self._server_started = False

    # ---- angr-management lifecycle hooks (duck-typed support) ----

    def on_workspace_initialized(self, workspace: Any) -> None:
        self._session_state.bind_workspace(workspace)
        self.refresh_active_context()
        self._ensure_server_started()

    def handle_workspace_initialized(self, workspace: Any) -> None:
        self.on_workspace_initialized(workspace)

    def on_workspace_changed(self, workspace: Any) -> None:
        self._session_state.bind_workspace(workspace)
        self.refresh_active_context()
        self._ensure_server_started()

    def handle_workspace_changed(self, workspace: Any) -> None:
        self.on_workspace_changed(workspace)

    def on_project_updated(self, project: Any) -> None:
        self._session_state.set_project(project)
        self.refresh_active_context()

    def handle_project_updated(self, project: Any) -> None:
        self.on_project_updated(project)

    def on_project_opened(self, project: Any) -> None:
        self._session_state.set_project(project)
        self.refresh_active_context()
        self._ensure_server_started()

    def handle_project_opened(self, project: Any) -> None:
        self.on_project_opened(project)

    def teardown(self) -> None:
        self._server.stop()
        self._server_started = False

    def deactivate(self) -> None:
        self.teardown()

    # ---- internal ----
    def refresh_active_context(self) -> None:
        """Re-sync project pointer from whichever workspace shape is active."""
        workspace = self._session_state.get_workspace() or getattr(self, "workspace", None)
        if workspace is not None:
            self._session_state.bind_workspace(workspace)

    def _ensure_server_started(self) -> None:
        if self._server_started:
            return
        result = self._server.start()
        logger.info("angr MCP server startup result: %s", result)
        self._server_started = True
