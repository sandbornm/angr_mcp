"""Session state adapter for angr-management workspace/project/program context."""

from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from typing import Any


@dataclass(frozen=True)
class ProgramDescriptor:
    """Lightweight, JSON-serializable descriptor for the active program."""

    name: str | None
    path: str | None
    architecture: str | None
    entry: int | None


class SessionState:
    """Thread-safe adapter over angr-management runtime objects."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._workspace: Any | None = None
        self._project: Any | None = None

    def bind_workspace(self, workspace: Any) -> None:
        with self._lock:
            self._workspace = workspace
            extracted = self._extract_project(workspace)
            if extracted is not None:
                self._project = extracted

    def set_project(self, project: Any) -> None:
        with self._lock:
            self._project = project

    def get_workspace(self) -> Any | None:
        with self._lock:
            return self._workspace

    def get_project(self) -> Any | None:
        with self._lock:
            if self._project is None and self._workspace is not None:
                self._project = self._extract_project(self._workspace)
            return self._project

    def require_project(self) -> Any:
        project = self.get_project()
        if project is None:
            raise RuntimeError("No active angr project is bound to the plugin session.")
        return project

    def resolve_project(self, binary_path: str | None = None) -> Any:
        """
        Resolve a project from active GUI state or an explicit binary path override.

        The override path supports deterministic headless/scripted operation.
        """
        if binary_path:
            angr = __import__("angr")
            return angr.Project(binary_path, auto_load_libs=False)
        return self.require_project()

    def get_program_descriptor(self) -> ProgramDescriptor:
        project = self.get_project()
        if project is None:
            return ProgramDescriptor(name=None, path=None, architecture=None, entry=None)

        filename = getattr(project, "filename", None)
        loader = getattr(project, "loader", None)
        main_object = getattr(loader, "main_object", None) if loader is not None else None
        arch = getattr(project, "arch", None)
        entry = getattr(main_object, "entry", None)
        binary_name = getattr(main_object, "binary", None) or filename
        arch_name = getattr(arch, "name", None)

        return ProgramDescriptor(
            name=str(binary_name) if binary_name is not None else None,
            path=str(filename) if filename is not None else None,
            architecture=str(arch_name) if arch_name is not None else None,
            entry=int(entry) if isinstance(entry, int) else None,
        )

    def _extract_project(self, workspace: Any) -> Any | None:
        candidates = (
            getattr(workspace, "project", None),
            getattr(workspace, "main_instance", None),
            getattr(getattr(workspace, "instance", None), "project", None),
        )
        for candidate in candidates:
            if candidate is None:
                continue
            # angr-management may expose project via nested object.
            if hasattr(candidate, "loader") or hasattr(candidate, "kb"):
                return candidate
            nested = getattr(candidate, "project", None)
            if nested is not None:
                return nested
        return None

    def refresh_gui(self) -> dict[str, Any]:
        """
        Best-effort request for angr-management UI refresh after state mutation.

        Different angr-management versions expose different refresh/update hooks.
        This method tries several known patterns and returns which hook succeeded.
        """
        workspace = self.get_workspace()
        if workspace is None:
            return {"updated": False, "reason": "no_workspace_bound"}

        refresh_candidates = (
            getattr(workspace, "reload", None),
            getattr(workspace, "refresh", None),
            getattr(getattr(workspace, "view_manager", None), "reload", None),
            getattr(getattr(workspace, "view_manager", None), "refresh", None),
            getattr(getattr(workspace, "main_instance", None), "refresh", None),
        )
        for fn in refresh_candidates:
            if callable(fn):
                try:
                    fn()
                    return {"updated": True, "hook": getattr(fn, "__name__", "callable")}
                except Exception:  # noqa: BLE001 - best effort only
                    continue
        return {"updated": False, "reason": "no_supported_refresh_hook_found"}
