# mitmproxy + MCP POC

## Goal
Validate that an MCP server (Python SDK, asyncio) can run inside a mitmproxy addon
without event loop conflicts, using a simple TCP transport for testing.

## Requirements
- Python 3.10+
- Virtual environment at `poc/.venv`

## Setup
```bash
/Users/moha/.local/bin/python3.10 -m venv poc/.venv
source poc/.venv/bin/activate
pip install mitmproxy mcp
```

Note: `pip` needed the legacy resolver to complete in this environment. After install,
`typing-extensions` and `h11` were upgraded to satisfy `mcp` runtime requirements,
which makes mitmproxy's version pins technically mismatched. The POC tests still
pass, but this should be resolved cleanly in the real integration plan.

## Run Tests
```bash
bash poc/test_poc.sh
```

## Results
- MCP server starts inside addon and listens on TCP (default `127.0.0.1:9876`).
- `tools/list` returns the `ping` tool.
- Proxy and MCP requests succeed together (curl via proxy + MCP ping).

## Recommendation
PROCEED with Addon Mode architecture.
