"""MCP transport layer configuration.

Supports three transport types:
- STDIO: Primary for Claude Desktop (stdin/stdout)
- SSE: Secondary for web-based clients (HTTP server)
- TCP: Testing/POC (line-delimited JSON-RPC)
"""

import asyncio
from typing import Literal, Union

import anyio
from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream
from mcp.server import NotificationOptions, Server
from mcp.server.stdio import stdio_server
from mcp.server.sse import SseServerTransport
from mcp.shared.message import SessionMessage
import mcp.types as types

TransportType = Literal["stdio", "sse", "tcp"]


async def start_stdio_transport(server: Server) -> None:
    """Start STDIO transport for Claude Desktop.

    Reads JSON-RPC messages from stdin and writes responses to stdout.
    This is the primary transport for Claude Desktop integration.

    Args:
        server: MCP Server instance to run
    """
    async with stdio_server() as (read_stream, write_stream):
        init_options = server.create_initialization_options(NotificationOptions())
        await server.run(read_stream, write_stream, init_options)


async def start_sse_transport(
    server: Server, host: str = "127.0.0.1", port: int = 9011
) -> None:
    """Start SSE transport for web clients.

    Creates an HTTP server that serves SSE (Server-Sent Events) for
    real-time communication with web-based MCP clients.

    Args:
        server: MCP Server instance to run
        host: Host to bind to (default: 127.0.0.1)
        port: Port to bind to (default: 9011)
    """
    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.responses import Response
    from starlette.routing import Mount, Route
    import uvicorn

    sse = SseServerTransport("/messages/")

    async def handle_sse(request: Request) -> Response:
        async with sse.connect_sse(
            request.scope,
            request.receive,
            request._send,  # type: ignore[attr-defined]
        ) as streams:
            init_options = server.create_initialization_options(NotificationOptions())
            await server.run(streams[0], streams[1], init_options)
        return Response()

    app = Starlette(
        routes=[
            Route("/sse", endpoint=handle_sse),
            Mount("/messages/", app=sse.handle_post_message),
        ]
    )

    config = uvicorn.Config(app, host=host, port=port, log_level="warning")
    server_instance = uvicorn.Server(config)
    await server_instance.serve()


async def start_tcp_transport(
    server: Server, host: str = "127.0.0.1", port: int = 9011
) -> asyncio.AbstractServer:
    """Start TCP transport (for testing/POC).

    Creates a TCP server that accepts line-delimited JSON-RPC messages.
    This is kept from the POC for testing purposes.

    Args:
        server: MCP Server instance to run
        host: Host to bind to (default: 127.0.0.1)
        port: Port to bind to (default: 9011)

    Returns:
        The asyncio TCP server instance
    """

    async def handle_client(
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        read_writer: MemoryObjectSendStream[Union[SessionMessage, Exception]]
        read_stream: MemoryObjectReceiveStream[Union[SessionMessage, Exception]]
        write_stream: MemoryObjectSendStream[SessionMessage]
        write_reader: MemoryObjectReceiveStream[SessionMessage]
        read_writer, read_stream = anyio.create_memory_object_stream(0)
        write_stream, write_reader = anyio.create_memory_object_stream(0)
        init_options = server.create_initialization_options(NotificationOptions())

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
            await server.run(read_stream, write_stream, init_options)

    tcp_server = await asyncio.start_server(handle_client, host, port)
    return tcp_server


async def serve_with_tcp(
    server: Server, host: str = "127.0.0.1", port: int = 9011
) -> None:
    """Serve MCP server with TCP transport (blocking).

    This is a convenience wrapper that starts the TCP server and
    serves forever. Used in the addon's _serve() method.

    Args:
        server: MCP Server instance to run
        host: Host to bind to (default: 127.0.0.1)
        port: Port to bind to (default: 9011)
    """
    tcp_server = await start_tcp_transport(server, host, port)
    async with tcp_server:
        await tcp_server.serve_forever()
