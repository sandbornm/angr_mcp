from angr_mcp_plugin.session_state import SessionState


class _Arch:
    name = "AMD64"


class _MainObject:
    entry = 0x401000
    binary = "fake.bin"


class _Loader:
    main_object = _MainObject()


class _Project:
    filename = "/tmp/fake.bin"
    arch = _Arch()
    loader = _Loader()
    kb = type("_KB", (), {"functions": {}, "strings": {}})()


class _Workspace:
    project = _Project()


def test_bind_workspace_and_descriptor():
    state = SessionState()
    state.bind_workspace(_Workspace())
    descriptor = state.get_program_descriptor()
    assert descriptor.name == "fake.bin"
    assert descriptor.path == "/tmp/fake.bin"
    assert descriptor.architecture == "AMD64"
    assert descriptor.entry == 0x401000


def test_require_project_raises_when_unbound():
    state = SessionState()
    try:
        state.require_project()
    except RuntimeError as exc:
        assert "No active angr project" in str(exc)
    else:
        raise AssertionError("Expected RuntimeError when no project is bound")
