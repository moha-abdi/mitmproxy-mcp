"""mitmproxy addon with MCP server for querying captured traffic."""

import asyncio
from typing import Optional, cast

from mitmproxy import ctx, http
from mitmproxy.addonmanager import Loader

from mcp.server import Server

from mitmproxy import flowfilter

from .storage import FlowStorage, set_storage
from .tools import (
    FLOW_TOOLS,
    handle_flow_tool,
    REPLAY_TOOLS,
    handle_replay_tool,
    INTERCEPT_TOOLS,
    handle_intercept_tool,
    CONFIG_TOOLS,
    handle_config_tool,
    get_parsed_filter,
)
from .transport import (
    TransportType,
    start_stdio_transport,
    start_sse_transport,
    serve_with_tcp,
    shutdown_sse_server,
)
from .privacy import init_redaction_engine, reset_redaction_engine


class MCPAddon:
    def __init__(self) -> None:
        self._server: Server = Server("mitmproxy-mcp")
        self._server_task: Optional[asyncio.Task] = None
        self._storage = FlowStorage()
        set_storage(self._storage)

        self._register_tools()

    def _register_tools(self) -> None:
        @self._server.list_tools()
        async def list_tools():
            return FLOW_TOOLS + REPLAY_TOOLS + INTERCEPT_TOOLS + CONFIG_TOOLS

        @self._server.call_tool()
        async def call_tool(name: str, arguments: dict):
            flow_tool_names = {t.name for t in FLOW_TOOLS}
            replay_tool_names = {t.name for t in REPLAY_TOOLS}
            intercept_tool_names = {t.name for t in INTERCEPT_TOOLS}
            config_tool_names = {t.name for t in CONFIG_TOOLS}

            if name in flow_tool_names:
                return await handle_flow_tool(name, arguments)
            elif name in replay_tool_names:
                return await handle_replay_tool(name, arguments)
            elif name in intercept_tool_names:
                return await handle_intercept_tool(name, arguments)
            elif name in config_tool_names:
                return await handle_config_tool(name, arguments)
            else:
                import mcp.types as types

                return [
                    types.TextContent(
                        type="text", text=f'{{"error": "Unknown tool: {name}"}}'
                    )
                ]

    def load(self, loader: Loader) -> None:
        loader.add_option(
            "mcp_transport",
            str,
            "stdio",
            "MCP transport type: stdio (default), sse, or tcp",
        )
        loader.add_option("mcp_port", int, 9011, "MCP server port (for sse/tcp)")
        loader.add_option("mcp_max_flows", int, 1000, "Maximum flows to store")
        loader.add_option(
            "mcp_redact",
            bool,
            False,
            "Redact sensitive data (tokens, keys, passwords) before sending to AI",
        )
        loader.add_option(
            "mcp_redact_patterns",
            str,
            "",
            'JSON array of custom regex patterns to redact (e.g., \'["secret", "token"]\')',
        )

    def configure(self, updated: set) -> None:
        if "mcp_max_flows" in updated:
            max_flows = int(cast(int, ctx.options.mcp_max_flows))
            self._storage = FlowStorage(max_flows=max_flows)
            set_storage(self._storage)

        if "mcp_redact" in updated or "mcp_redact_patterns" in updated:
            if ctx.options.mcp_redact:
                patterns_str = cast(str, ctx.options.mcp_redact_patterns)
                custom_patterns = None
                if patterns_str:
                    import json

                    custom_patterns = json.loads(patterns_str)
                init_redaction_engine(custom_patterns)
            else:
                reset_redaction_engine()

    def running(self) -> None:
        loop = asyncio.get_running_loop()
        self._server_task = loop.create_task(self._serve())

    async def _serve(self) -> None:
        transport: TransportType = cast(TransportType, ctx.options.mcp_transport)
        port = int(cast(int, ctx.options.mcp_port))
        host = "127.0.0.1"

        if transport == "stdio":
            ctx.log.info("MCP server starting with STDIO transport")
            await start_stdio_transport(self._server)
        elif transport == "sse":
            ctx.log.info(f"MCP server starting with SSE transport on {host}:{port}")
            await start_sse_transport(self._server, host, port)
        elif transport == "tcp":
            ctx.log.info(f"MCP server starting with TCP transport on {host}:{port}")
            await serve_with_tcp(self._server, host, port)
        else:
            ctx.log.error(f"Unknown transport type: {transport}")
            raise ValueError(f"Unknown transport type: {transport}")

    def request(self, flow: http.HTTPFlow) -> None:
        self._storage.add(flow)
        parsed_filter = get_parsed_filter()
        if parsed_filter and flowfilter.match(parsed_filter, flow):
            flow.intercept()

    def response(self, flow: http.HTTPFlow) -> None:
        self._storage.add(flow)

    def done(self) -> None:
        shutdown_sse_server()
        if self._server_task is not None:
            self._server_task.cancel()


addons = [MCPAddon()]
