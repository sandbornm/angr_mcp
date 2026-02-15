# angr MCP Plugin

[![CI](https://github.com/sandbornm/angr_mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/sandbornm/angr_mcp/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

An [angr-management](https://github.com/angr/angr-management) plugin that embeds an [MCP](https://modelcontextprotocol.io/) (Model Context Protocol) server, exposing angr's binary analysis capabilities to LLM clients like Claude Code, Cursor, and other MCP-compatible tools.

## Features

- **Live GUI integration** -- MCP tools bind to the active angr-management workspace, so LLM agents operate on the same binary you have open
- **Function analysis** -- List, inspect, and decompile functions from the angr knowledge base
- **Symbolic execution** -- Build CFGs, explore paths with constraints, and solve for stdin
- **Live mutations** -- Rename functions and set comments that update the GUI in real time
- **Batch operations** -- Run multiple analysis actions in a single call
- **Snapshot export/import** -- Versioned JSON contract for reproducible analysis state transfer
- **Headless dev mode** -- Run the MCP server standalone without angr-management for development and testing

## MCP Tools

| Tool | Category | Description |
|------|----------|-------------|
| `am_get_current_program` | Core | Get metadata for the active binary |
| `am_list_functions` | Core | Paginated function listing from the knowledge base |
| `am_get_function` | Core | Detailed info for a function at a given address |
| `am_decompile_function` | Core | Decompile a function to pseudocode |
| `am_list_strings` | Core | Paginated string listing |
| `am_get_xrefs_to` | Core | Cross-references to a target address |
| `am_rename_function` | Core | Rename a function (live GUI update) |
| `am_set_comment` | Core | Set a comment at an address (live GUI update) |
| `am_angr_entry` | Symbolic | Get the binary entry point address |
| `am_angr_cfg` | Symbolic | Build a CFG and return node/edge summary |
| `am_angr_explore` | Symbolic | Symbolic execution with find/avoid constraints |
| `am_sync_export` | Automation | Export current analysis state as a snapshot |
| `am_sync_import` | Automation | Import and optionally apply a snapshot |
| `am_run_batch` | Automation | Execute multiple actions in one call |

## Installation

Requires Python 3.10+. Install with [uv](https://docs.astral.sh/uv/) (recommended) or pip:

```bash
# Clone the repo
git clone https://github.com/sandbornm/angr_mcp.git
cd angr_mcp

# Install with dev dependencies
uv pip install -e ".[dev]"

# Include angr/angr-management in the same environment
uv pip install -e ".[dev,angr]"
```

## Usage

### Plugin mode (angr-management GUI)

1. Symlink the plugin into angr-management's plugin directory:

```bash
mkdir -p ~/.local/share/angr-management/plugins
ln -sfn "$(pwd)/src/angr_mcp_plugin" ~/.local/share/angr-management/plugins/angr_mcp
```

2. Restart angr-management and enable **angr MCP Plugin** from the plugin manager.

3. Open a binary -- the MCP server starts automatically on `http://127.0.0.1:8766/mcp`.

### Dev mode (standalone server)

Run the MCP server without angr-management for development:

```bash
angr-mcp-dev-server
```

### Connect your LLM client

Add this to your MCP client configuration (Cursor, Claude Code, etc.):

```json
{
  "mcpServers": {
    "angr-mcp": {
      "url": "http://127.0.0.1:8766/mcp"
    }
  }
}
```

## Configuration

The plugin reads these environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `ANGR_MCP_TRANSPORT` | `streamable-http` | MCP transport type |
| `ANGR_MCP_HOST` | `127.0.0.1` | Server bind address |
| `ANGR_MCP_PORT` | `8766` | Server port |

## Development

```bash
# Install dev dependencies
uv pip install -e ".[dev]"

# Run tests
pytest

# Lint
ruff check src/ tests/

# Type check
mypy src/
```

### Validate sync snapshots

```bash
angr-mcp-validate-sync snapshot.json
```

## Architecture

```
src/angr_mcp_plugin/
  plugin.py          # angr-management plugin entrypoint
  mcp_server.py      # Embedded MCP server (FastMCP + background thread)
  session_state.py   # Thread-safe workspace/project binding
  sync_contract.py   # Versioned snapshot export/import schema
  cli.py             # Dev server and validation CLI
  plugin.toml        # angr-management plugin metadata
  tools/
    core.py          # GUI-bound analysis tools (8 tools)
    symbolic.py      # Symbolic execution helpers (3 tools)
    automation.py    # Batch and sync tools (3 tools)
```

## License

[Apache 2.0](LICENSE)
