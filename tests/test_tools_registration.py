import json
from collections.abc import Callable
from typing import Any

from angr_mcp_plugin.session_state import SessionState
from angr_mcp_plugin.tools import register_automation_tools, register_core_tools, register_symbolic_tools


class FakeMCP:
    def __init__(self) -> None:
        self.tools: dict[str, Callable[..., Any]] = {}

    def tool(self) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            self.tools[fn.__name__] = fn
            return fn

        return decorator


class FakeFunction:
    def __init__(self, name: str, size: int, is_plt: bool = False) -> None:
        self.name = name
        self.size = size
        self.is_plt = is_plt
        self.is_syscall = False


class FakeXRef:
    def __init__(self, src: int, dst: int, ref_type: str) -> None:
        self.ins_addr = src
        self.dst = dst
        self.type = ref_type


class FakeXRefs:
    def get_xrefs_by_dst(self, dst: int):  # noqa: ANN001
        return [FakeXRef(0x401020, dst, "CodeRef")]


class FakeCfgGraph:
    @staticmethod
    def number_of_nodes() -> int:
        return 3

    @staticmethod
    def number_of_edges() -> int:
        return 2


class FakeCfg:
    graph = FakeCfgGraph()


class FakeAnalyses:
    @staticmethod
    def CFGFast(normalize: bool = True) -> FakeCfg:  # noqa: N802
        assert normalize is True
        return FakeCfg()


class FakeProject:
    filename = "/tmp/fake.bin"
    arch = type("_Arch", (), {"name": "AMD64"})()
    loader = type(
        "_Loader",
        (),
        {"main_object": type("_Obj", (), {"entry": 0x401000, "binary": "fake.bin"})()},
    )()
    analyses = FakeAnalyses()
    kb = type(
        "_KB",
        (),
        {
            "functions": {0x401000: FakeFunction("main", 32), 0x401100: FakeFunction("helper", 16)},
            "strings": {0x402000: "hello", 0x402100: "world"},
            "xrefs": FakeXRefs(),
            "comments": {},
        },
    )()


def _register_all_tools() -> tuple[FakeMCP, SessionState]:
    mcp = FakeMCP()
    state = SessionState()
    state.set_project(FakeProject())
    register_core_tools(mcp, state)
    register_symbolic_tools(mcp, state)
    register_automation_tools(mcp, state)
    return mcp, state


def test_core_tools_work_with_active_project():
    mcp, _ = _register_all_tools()
    program = mcp.tools["am_get_current_program"]()
    funcs = mcp.tools["am_list_functions"](offset=0, limit=10)
    fn = mcp.tools["am_get_function"]("0x401000")
    xrefs = mcp.tools["am_get_xrefs_to"]("0x401000")
    assert program["name"] == "fake.bin"
    assert funcs["total"] == 2
    assert fn["name"] == "main"
    assert xrefs["total"] == 1


def test_live_update_tools_mutate_project_state():
    mcp, state = _register_all_tools()
    rename_result = mcp.tools["am_rename_function"]("0x401000", "entry_main")
    comment_result = mcp.tools["am_set_comment"]("0x401000", "checked by mcp")
    project = state.require_project()
    assert rename_result["new_name"] == "entry_main"
    assert project.kb.functions[0x401000].name == "entry_main"
    assert comment_result["new_comment"] == "checked by mcp"
    assert project.kb.comments[0x401000] == "checked by mcp"


def test_symbolic_cfg_tool_summary():
    mcp, _ = _register_all_tools()
    cfg = mcp.tools["am_angr_cfg"](timeout=1)
    assert cfg["nodes"] == 3
    assert cfg["edges"] == 2


def test_automation_export_and_batch():
    mcp, _ = _register_all_tools()
    export = mcp.tools["am_sync_export"]()
    assert "snapshot" in export
    batch = mcp.tools["am_run_batch"]([{"type": "current_program"}, {"type": "sync_export"}, {"type": "unsupported"}])
    assert batch["total"] == 3
    assert batch["failed"] == 1


def test_sync_import_applies_changes():
    mcp, state = _register_all_tools()
    snapshot = {
        "schema_version": "1.0",
        "program": {"name": "fake.bin", "path": "/tmp/fake.bin", "architecture": "AMD64", "entry": 4198400},
        "generated_at_unix": 1700000000,
        "functions": [{"address": "0x401000", "name": "main_after_import"}],
        "strings": [],
        "comments": [{"address": "0x401000", "text": "imported comment"}],
        "metadata": {},
    }
    result = mcp.tools["am_sync_import"](snapshot_json=json.dumps(snapshot), apply_changes=True)
    project = state.require_project()
    assert result["applied"]["renamed_functions"] == 1
    assert result["applied"]["applied_comments"] == 1
    assert project.kb.functions[0x401000].name == "main_after_import"
    assert project.kb.comments[0x401000] == "imported comment"
