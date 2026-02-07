# mitmproxy-mcp Development Guide for AI Agents

> **Project**: MCP Server for mitmproxy -- HTTP traffic analysis via Model Context Protocol
>
> **Status**: Feature-complete (v0.1.0), pre-PyPI publish
>
> **Stack**: Python 3.10+, mitmproxy 11, MCP SDK, Pydantic v2 (v1 compat API)
>
> **Repo**: [moha-abdi/mitmproxy-mcp](https://github.com/moha-abdi/mitmproxy-mcp)

---

## Architecture

MCP server runs inside mitmproxy as an addon. Not a separate process -- it's embedded directly in the proxy event loop via the `running()` hook and `asyncio.create_task()`.

```
mitmproxy (proxy process)
  addon.py (thin wrapper, loads from mitmproxy_mcp.addon)
    MitmproxyAddon
      flow hooks: request(), response(), error()
      MCP server: SSE on port 9011 (default)
        20 tools across 4 categories
```

The SSE transport uses Starlette + uvicorn. Each connecting client gets its own `ServerSession` with a unique session ID -- multi-client is handled natively by the MCP SDK.

---

## Dependency Management

Always use `uv`, never `pip`:

```bash
uv pip install -e ".[dev]"
uv pip install <package>
uv pip install --upgrade <package>
```

---

## Python Version

- **Minimum**: Python 3.10 (required by `mcp` package)
- **System Python**: 3.9.6 (too old, don't use)
- **Available**: `/Users/moha/.local/bin/python3.10`

```bash
/Users/moha/.local/bin/python3.10 -m venv .venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

---

## Project Structure

```
mitmproxy-mcp/
  addon.py                  thin wrapper (mitmproxy loads this)
  pyproject.toml            package config, dependencies
  pytest.ini                asyncio_mode=auto
  README.md                 user docs with client setup guides
  SKILL.md                  agent skill definition (agentskills.io format)
  LICENSE                   MIT
  .github/workflows/ci.yml  CI: ruff + mypy + pytest

  mitmproxy_mcp/            main package
    __init__.py             version = "0.1.0"
    __main__.py             CLI stub
    addon.py                mitmproxy addon, MCP server lifecycle
    models.py               pydantic models for flow serialization
    storage.py              thread-safe in-memory flow storage
    privacy.py              redaction engine (tokens, keys, passwords, JWTs)
    transport.py            stdio, sse, tcp transport layer
    tools/
      __init__.py
      flows.py              8 flow query/export tools
      replay.py             4 replay and modification tools
      intercept.py          5 interception control tools
      config.py             3 proxy configuration tools

  tests/                    174 tests, all passing
    conftest.py             shared fixtures
    test_models.py          model serialization tests
    test_flow_tools.py      flow query tool tests
    test_replay_tools.py    replay tool tests
    test_intercept_tools.py intercept tool tests
    test_config_tools.py    config tool tests
    test_privacy.py         redaction engine tests
    test_transport.py       transport layer tests
    test_integration.py     addon integration tests

  poc/                      original proof of concept (archived)
```

---

## Running the Server

### Via config (recommended)

`~/.mitmproxy/config.yaml`:

```yaml
scripts:
  - /absolute/path/to/mitmproxy-mcp/addon.py

mcp_transport: sse
mcp_port: 9011
```

Then run mitmproxy normally:

```bash
mitmproxy      # interactive TUI
mitmweb        # web interface
mitmdump       # headless
```

### Via flags

```bash
mitmdump -s addon.py --set mcp_transport=sse --set mcp_port=9011
```

The MCP server starts automatically at `http://localhost:9011/sse`.

---

## Options

| Option | Default | Description |
|--------|---------|-------------|
| `mcp_transport` | `stdio` | Transport: `stdio`, `sse`, or `tcp` |
| `mcp_port` | `9011` | Port for SSE/TCP transport |
| `mcp_max_flows` | `1000` | Max flows in memory (oldest evicted first) |
| `mcp_redact_patterns` | built-in | Additional redaction patterns as JSON array |

---

## Tools (20 total)

### Flow tools (8): `tools/flows.py`
get_flows, get_flow_by_id, search_flows, get_flow_request, get_flow_response, clear_flows, get_flow_count, export_flows

### Replay tools (4): `tools/replay.py`
replay_request, send_request, modify_and_send, duplicate_flow

### Intercept tools (5): `tools/intercept.py`
set_intercept_filter, get_intercepted_flows, resume_flow, resume_all, drop_flow

### Config tools (3): `tools/config.py`
get_options, set_option, get_status

---

## Coding Conventions

### Pydantic

We use Pydantic v2 but with the v1 compatibility API (`class Config` instead of `model_config`, `.dict()` instead of `.model_dump()`). This is because mitmproxy's internal pydantic usage expects v1 patterns.

```python
class MyModel(BaseModel):
    field: str

    class Config:
        arbitrary_types_allowed = True

model_dict = my_model.dict()
```

### mitmproxy Flow Structure

```python
flow.id                  # str: unique ID
flow.request.method      # str: "GET", "POST", etc.
flow.request.url         # str: full URL
flow.request.headers     # Headers object (iterate with .items())
flow.request.content     # bytes: body
flow.response            # can be None if request hasn't completed
flow.response.status_code
flow.response.headers
flow.response.content    # bytes: body
flow.timestamp_start     # float
flow.error               # optional error message
```

### Headers to dict

```python
result = {}
for name, value in headers.items():
    key = name if isinstance(name, str) else name.decode('utf-8')
    val = value if isinstance(value, str) else value.decode('utf-8')
    if key in result:
        result[key] = f"{result[key]}, {val}"
    else:
        result[key] = val
```

### MCP Tool Pattern

Each tool module exports a list of `types.Tool` definitions and a handler function:

```python
TOOLS = [types.Tool(name="...", description="...", inputSchema={...})]

async def handle_tool(name: str, arguments: dict) -> str:
    if name == "my_tool":
        return json.dumps(result)
    raise ValueError(f"Unknown tool: {name}")
```

The addon's `call_tool()` dispatches to the right handler based on tool name.

### Adding a New Tool

1. Add `types.Tool(...)` to the appropriate module's tool list
2. Add handler logic in the same module's `handle_*_tool()` function
3. Write tests
4. Run `pytest tests/ -v && ruff check . && mypy`

---

## Testing

```bash
# all 174 tests
pytest tests/ -v

# specific file
pytest tests/test_flow_tools.py -v

# with coverage
pytest tests/ --cov=mitmproxy_mcp --cov-report=html

# lint
ruff check .

# type check
mypy
```

Test utilities:

```python
from mitmproxy.test import tflow

flow = tflow.tflow(resp=True)   # mock flow with response
flow = tflow.tflow()            # without response
```

---

## Privacy / Redaction

The `privacy.py` module automatically redacts sensitive data before it reaches the AI:

- Bearer tokens, Basic auth credentials
- API keys (headers and query params)
- Passwords, secrets, session IDs
- JWTs
- Auth cookies

Bodies are truncated to 10KB. Custom patterns can be added via `mcp_redact_patterns`.

---

## Known Gotchas

### Starlette SSE handler

The SSE transport uses `SseServerTransport` from the MCP SDK. When wiring it into Starlette routes, the `/sse` endpoint must be a proper Starlette route handler, not a raw ASGI function. The `Request` object must come from Starlette, not from the raw ASGI scope.

### Asyncio coexistence

The MCP server runs inside mitmproxy's existing asyncio event loop. We use `asyncio.get_running_loop().create_task()` in the addon's `running()` hook. No separate thread or subprocess needed.

### mypy and intercept.py

Don't use type annotations on `flow_id` in elif branches in `intercept.py` -- it triggers mypy `no-redef` errors. Use inline casts or assert statements instead.

### uvicorn log level

Set to `warning` to avoid flooding mitmproxy's output with HTTP access logs for every MCP message.

---

## CI

GitHub Actions (`.github/workflows/ci.yml`): ruff check, mypy, pytest (174 tests). All green on `main`.

---

## SKILL.md

The project includes a `SKILL.md` for the [agentskills.io](https://agentskills.io) / `npx skills` ecosystem:

```yaml
---
name: mitmproxy-mcp       # required, must match repo/directory name
description: ...           # required, max 1024 chars
license: MIT
---
# Markdown body with agent instructions (<500 lines)
```

Install with: `npx skills add moha-abdi/mitmproxy-mcp`

---

## Dependencies

### Core
- `mitmproxy>=10.0.0` -- proxy server
- `mcp>=1.0.0` -- MCP SDK (requires Python 3.10+)
- `pydantic>=2.0.0` -- data validation (v1 compat API)

### Dev
- `pytest>=7.0.0`, `pytest-asyncio>=0.21.0`, `pytest-cov>=4.0.0`
- `ruff>=0.1.0`
- `mypy>=1.0.0`

---

## Resources

- **Project root**: `/Users/moha/Projects/mitmproxy_mcp/`
- **GitHub**: https://github.com/moha-abdi/mitmproxy-mcp
- **mitmproxy docs**: https://docs.mitmproxy.org/
- **MCP spec**: https://modelcontextprotocol.io/
- **Skills spec**: https://agentskills.io/
