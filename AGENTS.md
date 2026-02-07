# mitmproxy-mcp Development Guide for AI Agents

> **Project**: MCP Server for mitmproxy - HTTP traffic analysis via Model Context Protocol
>
> **Status**: Active Development (v0.1.0)
>
> **Stack**: Python 3.10+, mitmproxy, MCP SDK, Pydantic

---

## Project Overview

This is an MCP (Model Context Protocol) server that runs inside mitmproxy as an addon, enabling AI agents to analyze HTTP traffic, replay requests, and control interception.

**Architecture**: Addon Mode - MCP server embedded directly in mitmproxy addon (not external process).

---

## Critical: Dependency Management

### ⚠️ ALWAYS USE `uv` - NEVER USE `pip`

```bash
# Install dependencies
uv pip install -e ".[dev]"

# Add new dependency
uv pip install <package>

# Upgrade dependency
uv pip install --upgrade <package>
```

**Why `uv`?**
- 10-100x faster than pip
- No dependency backtracking issues
- Used throughout this project

**Never run**: `pip install` (too slow, causes resolver conflicts)

---

## Python Version Requirements

- **Minimum**: Python 3.10 (required by `mcp` package)
- **System Python**: 3.9.6 (too old, don't use)
- **Available**: `/Users/moha/.local/bin/python3.10`

**Virtual Environment**:
```bash
# Create venv with Python 3.10
/Users/moha/.local/bin/python3.10 -m venv .venv

# Activate
source .venv/bin/activate

# Install
uv pip install -e ".[dev]"
```

---

## Project Structure

```
mitmproxy_mcp/
├── AGENTS.md           # This file
├── pyproject.toml      # Package config, dependencies
├── pytest.ini          # pytest config (asyncio_mode=auto)
├── README.md           # User documentation
├── .gitignore          # Python patterns
│
├── mitmproxy_mcp/      # Main package (WRONG PLACE, should be root-level)
│   ├── __init__.py     # version = "0.1.0"
│   ├── __main__.py     # CLI stub
│   ├── addon.py        # mitmproxy addon with MCP server
│   ├── models.py       # Pydantic models for flow serialization
│   ├── storage.py      # In-memory flow storage
│   └── tools/
│       ├── __init__.py
│       └── flows.py    # 8 MCP tools for flow operations
│
├── tests/              # Test suite
│   ├── __init__.py
│   ├── test_models.py       # Model tests (31 tests)
│   └── test_flow_tools.py   # Flow tool tests (27 tests)
│
└── poc/                # Proof of concept
    ├── .venv/          # Separate Python 3.10 venv
    ├── addon.py        # Minimal POC addon
    ├── test_poc.sh     # POC validation script
    └── README.md       # POC results
```

**⚠️ STRUCTURAL ISSUE**: Package name mismatch
- PyPI name: `mitmproxy-mcp` (hyphen)
- Python import: `mitmproxy_mcp` (underscore)
- **Current bug**: Main package is nested inside project root

---

## Coding Conventions

### Pydantic Version

**Use Pydantic v1** (1.10.26), not v2:

```python
# ✅ Correct (Pydantic v1)
from pydantic import BaseModel

class MyModel(BaseModel):
    field: str
    
    class Config:
        arbitrary_types_allowed = True

model_dict = my_model.dict()
model_json = my_model.json()
schema = MyModel.schema()

# ❌ Wrong (Pydantic v2 API)
model_config = ConfigDict(...)  # Don't use
model.model_dump_json()        # Use .json() instead
MyModel.model_json_schema()    # Use .schema() instead
```

### mitmproxy Flow Structure

```python
# HTTPFlow attributes
flow.id                  # Unique ID
flow.request            # Request object
flow.response           # Response object (can be None)
flow.timestamp_start    # Request start time
flow.timestamp_created  # Flow created time (use as end time)
flow.error             # Error message (if failed)

# Request attributes
request.method          # str: "GET", "POST", etc.
request.url             # str: full URL
request.headers         # Headers object (use .items())
request.content         # bytes: request body
request.timestamp_start # float: timestamp

# Response attributes
response.status_code    # int: 200, 404, etc.
response.reason         # str: "OK", "Not Found"
response.headers        # Headers object
response.content        # bytes: response body
response.timestamp_start # float: timestamp
```

### Headers Conversion

```python
# mitmproxy Headers → Dict[str, str]
from mitmproxy.net.http import Headers

def headers_to_dict(headers: Headers) -> Dict[str, str]:
    """Convert mitmproxy Headers to dict."""
    result = {}
    for name, value in headers.items():
        # Decode bytes if needed
        key = name if isinstance(name, str) else name.decode('utf-8')
        val = value if isinstance(value, str) else value.decode('utf-8')
        
        # Handle multi-value headers
        if key in result:
            result[key] = f"{result[key]}, {val}"
        else:
            result[key] = val
    return result
```

### Body Truncation

```python
# Default: 10KB max body size
MAX_BODY_SIZE = 10 * 1024

def truncate_body(content: Optional[bytes], max_size: int = MAX_BODY_SIZE) -> Optional[str]:
    """Truncate and decode body content."""
    if not content:
        return None
    
    # Try UTF-8 decode
    try:
        decoded = content.decode('utf-8')
        if len(content) > max_size:
            return f"{decoded[:max_size]}\n... [TRUNCATED - {len(content) - max_size} bytes omitted]"
        return decoded
    except UnicodeDecodeError:
        # Fallback to base64
        import base64
        encoded = base64.b64encode(content).decode('ascii')
        if len(content) > max_size:
            return f"{encoded[:max_size]}\n... [TRUNCATED BINARY - {len(content) - max_size} bytes omitted]"
        return f"<binary: {encoded}>"
```

### MCP Tool Pattern

```python
import mcp.types as types
from mcp.server import Server

# Tool definition
@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    """Handle MCP tool calls."""
    if name == "my_tool":
        result = do_something(arguments)
        return [types.TextContent(type="text", text=result)]
    
    return [types.TextContent(type="text", text=f"Unknown tool: {name}")]

# Tool listing
@server.list_tools()
async def list_tools() -> list[types.Tool]:
    """List available tools."""
    return [
        types.Tool(
            name="my_tool",
            description="What the tool does",
            inputSchema={
                "type": "object",
                "properties": {
                    "param": {"type": "string", "description": "Parameter description"}
                },
                "required": ["param"],
                "additionalProperties": False
            }
        )
    ]
```

---

## Testing

### Running Tests

```bash
# All tests
.venv/bin/pytest tests/ -v

# Specific test file
.venv/bin/pytest tests/test_models.py -v

# With coverage
.venv/bin/pytest tests/ --cov=mitmproxy_mcp --cov-report=html
```

### Test Utilities

```python
from mitmproxy.test import tflow

# Create mock HTTPFlow
flow = tflow.tflow()                # Without response
flow = tflow.tflow(resp=True)      # With response
flow = tflow.tflow(resp=False)     # Explicitly without
```

### Test Structure

- **Unit tests**: Test individual functions/classes
- **Integration tests**: Test with real mitmproxy addon
- **POC tests**: Located in `poc/test_poc.sh`

---

## Running the Server

### Development Mode

```bash
# Start mitmproxy with addon
mitmdump -s mitmproxy_mcp/addon.py -p 8080

# Or with POC addon
mitmdump -s poc/addon.py -p 8082 --set mcp_port=9876
```

### Testing with Real Traffic

```bash
# Terminal 1: Start proxy
mitmdump -s mitmproxy_mcp/addon.py -p 8080

# Terminal 2: Send requests
curl -x http://localhost:8080 http://httpbin.org/get
curl -x http://localhost:8080 http://httpbin.org/post -d "test=data"

# Terminal 3: Query via MCP tools
# (TODO: Add MCP client instructions)
```

---

## Known Issues & Gotchas

### 1. Dependency Conflict: mitmproxy vs mcp

**Issue**: `mcp` requires `typing-extensions>=4.0` and `h11>=0.14`, but mitmproxy pins older versions.

**Current Status**: POC works despite version mismatches, but needs proper resolution for production.

**Solution**: TBD - May need to relax version constraints or use fork.

### 2. POC vs Main Package

**Issue**: POC has its own `.venv` with Python 3.10, main package uses system Python 3.9.

**Status**: Main package now has `.venv` with Python 3.10.

**Action**: Keep POC separate for validation, main package for development.

### 3. Asyncio Coexistence

**Validated**: MCP server (asyncio) coexists with mitmproxy's event loop without deadlocks.

**Pattern**: Use `asyncio.get_running_loop().create_task()` to start MCP server in addon's `running()` hook.

---

## Development Workflow

### Adding a New Tool

1. **Define tool in `tools/flows.py`**:
   ```python
   FLOW_TOOLS.append(types.Tool(
       name="new_tool",
       description="What it does",
       inputSchema={...}
   ))
   ```

2. **Implement handler**:
   ```python
   async def handle_new_tool(args: dict) -> str:
       # Implementation
       pass
   ```

3. **Add to `handle_flow_tool()`**:
   ```python
   if name == "new_tool":
       return await handle_new_tool(arguments)
   ```

4. **Update `addon.py` to register tool**

5. **Write tests in `tests/test_flow_tools.py`**

6. **Verify**: `pytest tests/test_flow_tools.py::test_new_tool -v`

### Updating Models

1. **Edit `models.py`** (remember: Pydantic v1 API)

2. **Update tests in `tests/test_models.py`**

3. **Verify**: `pytest tests/test_models.py -v`

4. **Update usage in `tools/flows.py` if needed**

---

## Documentation Updates

### When to Update AGENTS.md

- New coding patterns discovered
- Dependency changes
- Structural changes
- New gotchas/workarounds
- Testing patterns

### Format

```markdown
## [Date] Topic

- Discovery: What was learned
- Impact: Why it matters
- Action: What to do
```

Append to end of file, never overwrite.

---

## Dependencies

### Core

- `mitmproxy>=10.0.0` - Proxy server, provides `http.HTTPFlow`
- `mcp>=1.0.0` - Model Context Protocol SDK (requires Python 3.10+)
- `pydantic>=2.0.0` - Data validation (but using v1 API compatibility)

### Dev

- `pytest>=7.0.0` - Test framework
- `pytest-asyncio>=0.21.0` - Async test support
- `ruff>=0.1.0` - Fast linter
- `mypy>=1.0.0` - Type checker

### Installation

```bash
# All at once with uv
uv pip install -e ".[dev]"
```

---

## Next Steps (Wave 2 Tasks)

Current progress: **3/12 tasks complete** (POC, Scaffolding, Models)

### Wave 2 (In Progress)

- ✅ Task 4: Flow storage & retrieval tools (8 tools) - **NEEDS VERIFICATION**
- ⏳ Task 5: Request replay tools (4 tools)
- ⏳ Task 6: STDIO transport layer
- ⏳ Task 7: Privacy/redaction engine

### Remaining Waves

- Wave 3: Interception control, config tools, skill definition, integration tests
- Final: Documentation & packaging

---

## Contact & Resources

- **Project Root**: `/Users/moha/Projects/mitmproxy-mcp/`
- **Plan**: `.sisyphus/plans/mitmproxy-mcp-server.md`
- **Notepad**: `.sisyphus/notepads/mitmproxy-mcp-server/`
- **mitmproxy docs**: https://docs.mitmproxy.org/
- **MCP spec**: https://modelcontextprotocol.io/
