#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="$ROOT_DIR/poc/.venv"
MITMDUMP_BIN="$VENV_DIR/bin/mitmdump"
MCP_PORT=9876
PROXY_PORT=8082

if [[ ! -x "$MITMDUMP_BIN" ]]; then
  echo "mitmdump not found at $MITMDUMP_BIN" >&2
  exit 1
fi

source "$VENV_DIR/bin/activate"

cleanup() {
  if [[ -n "${MITM_PID:-}" ]]; then
    kill "$MITM_PID" >/dev/null 2>&1 || true
    wait "$MITM_PID" >/dev/null 2>&1 || true
  fi
}

trap cleanup EXIT

"$MITMDUMP_BIN" -s "$ROOT_DIR/poc/addon.py" -p "$PROXY_PORT" --set mcp_port="$MCP_PORT" >/tmp/mitmdump-poc.log 2>&1 &
MITM_PID=$!

sleep 3

INIT_REQ='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"poc","version":"0.0.0"}}}'
LIST_REQ='{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
PING_REQ='{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"ping","arguments":{}}}'

echo "Scenario 1: MCP tools/list over TCP"
SCENARIO1_RESP=$(printf "%s\n%s\n" "$INIT_REQ" "$LIST_REQ" | nc -w 2 127.0.0.1 "$MCP_PORT")
echo "$SCENARIO1_RESP" | grep -q '"name":"ping"'

echo "Scenario 2: Proxy + MCP coexist"
curl -fsS -x "http://localhost:$PROXY_PORT" "http://httpbin.org/get" >/tmp/mitmproxy-poc-curl.json

SCENARIO2_RESP=$(printf "%s\n%s\n" "$INIT_REQ" "$PING_REQ" | nc -w 2 127.0.0.1 "$MCP_PORT")
echo "$SCENARIO2_RESP" | grep -q 'pong'

echo "POC OK"
