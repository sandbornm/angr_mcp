from unittest.mock import MagicMock, patch

from angr_mcp_plugin.plugin import AngrMCPPlugin


def test_plugin_starts_server_on_workspace_init():
    with patch("angr_mcp_plugin.plugin.AngrEmbeddedMCPServer") as mock_server_cls:
        mock_server = MagicMock()
        mock_server.start.return_value = {"status": "started"}
        mock_server_cls.return_value = mock_server

        plugin = AngrMCPPlugin(workspace=object())
        plugin.on_workspace_initialized(object())

        mock_server.start.assert_called_once()


def test_plugin_stops_server_on_teardown():
    with patch("angr_mcp_plugin.plugin.AngrEmbeddedMCPServer") as mock_server_cls:
        mock_server = MagicMock()
        mock_server_cls.return_value = mock_server

        plugin = AngrMCPPlugin(workspace=object())
        plugin.teardown()

        mock_server.stop.assert_called_once()


def test_project_update_rebinds_context():
    with patch("angr_mcp_plugin.plugin.AngrEmbeddedMCPServer") as mock_server_cls:
        mock_server_cls.return_value = MagicMock()
        plugin = AngrMCPPlugin(workspace=object())
        project = object()
        plugin.on_project_updated(project)
        assert plugin._session_state.get_project() is project
