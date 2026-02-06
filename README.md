# mitmproxy-mcp

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

MCP server for [mitmproxy](https://mitmproxy.org/) -- analyze, intercept, and replay HTTP/HTTPS traffic through any MCP client.

## What is this

mitmproxy-mcp runs as a mitmproxy addon. It embeds an [MCP](https://modelcontextprotocol.io/) server directly in the proxy process, giving AI agents (Claude, OpenCode, etc.) access to 20 tools for traffic analysis, request replay, interception control, and proxy configuration.

All captured data stays in-memory. Sensitive values (tokens, passwords, API keys, JWTs) are automatically redacted before being sent to the AI.

## Installation

```bash
git clone https://github.com/moha-abdi/mitmproxy-mcp.git
cd mitmproxy-mcp

python3.10 -m venv .venv
source .venv/bin/activate

# recommended
uv pip install -e ".[dev]"

# or with pip
pip install -e ".[dev]"
```

Requires Python 3.10+ and mitmproxy >= 10.0.0.

## Setup

The addon auto-loads via mitmproxy's config file. Create or edit `~/.mitmproxy/config.yaml`:

```yaml
scripts:
  - /absolute/path/to/mitmproxy-mcp/addon.py

mcp_transport: sse
mcp_port: 9876
```

Then just start mitmproxy normally:

```bash
mitmproxy      # interactive TUI
mitmweb        # web interface
mitmdump       # headless
```

The MCP server starts automatically on port 9876.

### Connecting from OpenCode

Add to `~/.config/opencode/opencode.json`:

```json
{
  "mcp": {
    "mitmproxy": {
      "type": "local",
      "command": ["npx", "-y", "supergateway", "--sse", "http://127.0.0.1:9876/sse"],
      "enabled": true
    }
  }
}
```

### Connecting from Claude Desktop

Add to your Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "mitmproxy": {
      "command": "mitmdump",
      "args": ["-s", "/absolute/path/to/addon.py", "-p", "8080"],
      "env": {
        "PYTHONPATH": "/absolute/path/to/mitmproxy-mcp"
      }
    }
  }
}
```

Note: Claude Desktop uses STDIO transport. Set `mcp_transport: stdio` in config.yaml, or pass `--set mcp_transport=stdio` on the command line.

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
| `mcp_port` | `9876` | Port for SSE/TCP transport |
| `mcp_max_flows` | `1000` | Max flows to keep in memory (oldest evicted first) |
| `mcp_redact_patterns` | built-in | Additional redaction patterns as JSON array |

Example:

```bash
mitmdump -s addon.py --set mcp_transport=sse --set mcp_port=9876 --set mcp_max_flows=5000
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
  addon.py          main mitmproxy addon
  models.py         pydantic models for flow serialization
  storage.py        thread-safe in-memory flow storage
  privacy.py        redaction engine
  transport.py      stdio, sse, tcp transport layer
  tools/
    flows.py        flow query tools
    replay.py       replay and modification tools
    intercept.py    interception control tools
    config.py       proxy configuration tools
  tests/            174 tests
```

## Development

```bash
# run tests
pytest tests/ -v

# run a specific test file
pytest tests/test_flow_tools.py -v

# with coverage
pytest tests/ --cov=mitmproxy_mcp --cov-report=html

# lint
ruff check .

# type check
mypy mitmproxy_mcp/ --ignore-missing-imports
```

## License

MIT
