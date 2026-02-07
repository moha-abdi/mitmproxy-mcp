import asyncio
from typing import cast

import anyio
from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream
from mitmproxy import ctx, http
from mitmproxy.addonmanager import Loader

import mcp.types as types
from mcp.server import NotificationOptions, Server
from mcp.shared.message import SessionMessage

# pyright: reportUnusedFunction=false


class MCPAddon:
    def __init__(self) -> None:
        self._server: Server[dict[str, object], object] = Server("mitmproxy-mcp-poc")
        self._tcp_server: asyncio.AbstractServer | None = None
        self._server_task: asyncio.Task[None] | None = None

        @self._server.list_tools()
        async def list_tools():
            return [
                types.Tool(
                    name="ping",
                    description="Simple liveness check",
                    inputSchema={
                        "type": "object",
                        "properties": {},
                        "additionalProperties": False,
                    },
                )
            ]

        @self._server.call_tool()
        async def call_tool(name: str, arguments: dict[str, object]):
            _ = arguments
            if name != "ping":
                return [types.TextContent(type="text", text=f"Unknown tool: {name}")]

            return [types.TextContent(type="text", text="pong")]

    def load(self, loader: Loader) -> None:
        loader.add_option("mcp_port", int, 9011, "MCP TCP port for POC")

    def running(self) -> None:
        loop = asyncio.get_running_loop()
        self._server_task = loop.create_task(self._serve())

    async def _serve(self) -> None:
        host = "127.0.0.1"
        port = int(cast(int, ctx.options.mcp_port))
        self._tcp_server = await asyncio.start_server(self._handle_client, host, port)
        async with self._tcp_server:
            await self._tcp_server.serve_forever()

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        read_writer: MemoryObjectSendStream[SessionMessage | Exception]
        read_stream: MemoryObjectReceiveStream[SessionMessage | Exception]
        write_stream: MemoryObjectSendStream[SessionMessage]
        write_reader: MemoryObjectReceiveStream[SessionMessage]
        read_writer, read_stream = anyio.create_memory_object_stream(0)
        write_stream, write_reader = anyio.create_memory_object_stream(0)
        init_options = self._server.create_initialization_options(NotificationOptions())

        async def tcp_reader() -> None:
            while True:
                line = await reader.readline()
                if not line:
                    await anyio.sleep(0.1)
                    await read_writer.aclose()
                    return
                text = line.decode("utf-8").strip()
                if not text:
                    continue
                try:
                    message = types.JSONRPCMessage.model_validate_json(text)
                except Exception as exc:
                    await read_writer.send(exc)
                    continue
                await read_writer.send(SessionMessage(message))

        async def tcp_writer() -> None:
            try:
                async with write_reader:
                    async for session_message in write_reader:
                        payload: str = session_message.message.model_dump_json(
                            by_alias=True,
                            exclude_none=True,
                        )
                        writer.write((payload + "\n").encode("utf-8"))
                        await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        async with anyio.create_task_group() as tg:
            tg.start_soon(tcp_reader)
            tg.start_soon(tcp_writer)
            await self._server.run(read_stream, write_stream, init_options)

    def request(self, flow: http.HTTPFlow) -> None:
        _ = flow
        return None

    def response(self, flow: http.HTTPFlow) -> None:
        _ = flow
        return None

    def done(self) -> None:
        if self._tcp_server is not None:
            self._tcp_server.close()
        if self._server_task is not None:
            _ = self._server_task.cancel()


addons = [MCPAddon()]
