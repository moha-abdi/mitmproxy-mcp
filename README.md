# mitmproxy-mcp

[![CI](https://github.com/moha-abdi/mitmproxy-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/moha-abdi/mitmproxy-mcp/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

MCP server for [mitmproxy](https://mitmproxy.org/) -- analyze, intercept, and replay HTTP/HTTPS traffic through any MCP client.

## What is this

mitmproxy-mcp runs as a mitmproxy addon. It embeds an [MCP](https://modelcontextprotocol.io/) server directly in the proxy process, giving AI agents access to 20 tools for traffic analysis, request replay, interception control, and proxy configuration.

All captured data stays in-memory. Sensitive values (tokens, passwords, API keys, JWTs) are automatically redacted before being sent to the AI.

## Installation

```bash
git clone https://github.com/moha-abdi/mitmproxy-mcp.git
cd mitmproxy-mcp

python3.10 -m venv .venv
source .venv/bin/activate

uv pip install -e ".[dev]"
```

Requires Python 3.10+ and mitmproxy >= 10.0.0.

## Setup

### 1. Configure mitmproxy

Create or edit `~/.mitmproxy/config.yaml`:

```yaml
scripts:
  - /absolute/path/to/mitmproxy-mcp/addon.py

mcp_transport: sse
mcp_port: 9011
```

### 2. Start mitmproxy

```bash
mitmproxy      # interactive TUI
mitmweb        # web interface
mitmdump       # headless
```

The MCP server starts automatically on `http://localhost:9011/sse`.

### 3. Connect your AI client

All clients connect to the same SSE endpoint. Make sure mitmproxy is running before connecting.

<details>
<summary><b>OpenCode</b></summary>

OpenCode's local type bridges via [supergateway](https://github.com/supercorp-ai/supergateway). Requires Node.js.

Add to `opencode.json` in your project root, or `~/.config/opencode/opencode.json` globally:

```json
{
  "mcp": {
    "mitmproxy": {
      "type": "local",
      "command": ["npx", "-y", "supergateway", "--sse", "http://127.0.0.1:9011/sse"],
      "enabled": true
    }
  }
}
```

</details>

<details>
<summary><b>Claude Code</b></summary>

Via the CLI (project-level):

```bash
claude mcp add --transport sse mitmproxy http://localhost:9011/sse
```

To add globally across all projects:

```bash
claude mcp add --scope user --transport sse mitmproxy http://localhost:9011/sse
```

Or add manually to `~/.claude.json`:

```json
{
  "mcpServers": {
    "mitmproxy": {
      "type": "sse",
      "url": "http://localhost:9011/sse"
    }
  }
}
```

</details>

<details>
<summary><b>Cursor</b></summary>

Add to `.cursor/mcp.json` in your project root:

```json
{
  "mcpServers": {
    "mitmproxy": {
      "url": "http://localhost:9011/sse"
    }
  }
}
```

</details>

<details>
<summary><b>Windsurf</b></summary>

Add to `~/.codeium/windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "mitmproxy": {
      "url": "http://localhost:9011/sse"
    }
  }
}
```

</details>

<details>
<summary><b>VS Code (Copilot)</b></summary>

Add to `.vscode/mcp.json` in your project root:

```json
{
  "servers": {
    "mitmproxy": {
      "type": "http",
      "url": "http://localhost:9011/sse"
    }
  }
}
```

</details>

<details>
<summary><b>Claude Desktop</b></summary>

Claude Desktop doesn't natively support SSE, so we use [supergateway](https://github.com/supercorp-ai/supergateway) to bridge SSE to STDIO. Requires Node.js.

Add to your config (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS, `%APPDATA%\Claude\claude_desktop_config.json` on Windows):

```json
{
  "mcpServers": {
    "mitmproxy": {
      "command": "npx",
      "args": ["-y", "supergateway", "--sse", "http://127.0.0.1:9011/sse"]
    }
  }
}
```

</details>

<details>
<summary><b>Other clients</b></summary>

Any MCP client that supports SSE transport can connect directly to:

```
http://localhost:9011/sse
```

If your client only supports STDIO, use [supergateway](https://github.com/supercorp-ai/supergateway) to bridge:

```bash
npx -y supergateway --sse http://127.0.0.1:9011/sse
```

</details>

## Tools

### Flow tools (8)

| Tool | Description |
|------|-------------|
| `get_flows` | List captured flows with pagination and filtering |
| `get_flow_by_id` | Get complete flow details |
| `search_flows` | Search flows by regex pattern |
| `get_flow_request` | Get request details |
| `get_flow_response` | Get response details |
| `clear_flows` | Clear all captured flows |
| `get_flow_count` | Count captured flows |
| `export_flows` | Export flows to HAR format |

### Replay tools (4)

| Tool | Description |
|------|-------------|
| `replay_request` | Replay a captured request as-is |
| `send_request` | Send a new HTTP request |
| `modify_and_send` | Modify a captured request and send it |
| `duplicate_flow` | Clone a flow for comparison |

### Intercept tools (5)

| Tool | Description |
|------|-------------|
| `set_intercept_filter` | Set filter expression (e.g. `~u example.com`) |
| `get_intercepted_flows` | List currently intercepted flows |
| `resume_flow` | Resume a single intercepted flow |
| `resume_all` | Resume all intercepted flows |
| `drop_flow` | Drop an intercepted flow |

### Config tools (3)

| Tool | Description |
|------|-------------|
| `get_options` | Get current mitmproxy options |
| `set_option` | Set a mitmproxy option (dangerous ones are blocked) |
| `get_status` | Get proxy status and version info |

## Options

Pass via `--set` flag or set in `~/.mitmproxy/config.yaml`:

| Option | Default | Description |
|--------|---------|-------------|
| `mcp_transport` | `stdio` | Transport: `stdio`, `sse`, or `tcp` |
| `mcp_port` | `9011` | Port for SSE/TCP transport |
| `mcp_max_flows` | `1000` | Max flows to keep in memory (oldest evicted first) |
| `mcp_redact_patterns` | built-in | Additional redaction patterns as JSON array |

Example:

```bash
mitmdump -s addon.py --set mcp_transport=sse --set mcp_port=9011 --set mcp_max_flows=5000
```

## Privacy

Sensitive data is redacted automatically before reaching the AI:

- Bearer tokens, Basic auth credentials
- API keys (header and query parameter)
- Passwords, secrets
- JWTs
- Session IDs, auth tokens, session cookies

Request and response bodies are truncated to 10KB to prevent context overflow.

You can add custom patterns:

```bash
mitmdump -s addon.py --set mcp_redact_patterns='["internal_secret", "x-custom-key"]'
```

## Project structure

```
mitmproxy-mcp/
  addon.py              thin wrapper for mitmproxy script loading
  mitmproxy_mcp/        main package
    __init__.py
    addon.py            mitmproxy addon with MCP server
    models.py           pydantic models for flow serialization
    storage.py          thread-safe in-memory flow storage
    privacy.py          redaction engine
    transport.py        stdio, sse, tcp transport layer
    tools/
      flows.py          flow query tools
      replay.py         replay and modification tools
      intercept.py      interception control tools
      config.py         proxy configuration tools
  tests/                test suite
```

## Development

```bash
# install in editable mode (required for imports to work)
uv pip install -e ".[dev]"

# run tests
pytest tests/ -v

# run a specific test file
pytest tests/test_flow_tools.py -v

# with coverage
pytest tests/ --cov=mitmproxy_mcp --cov-report=html

# lint
ruff check .

# type check
mypy
```

## License

MIT
