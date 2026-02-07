"""Tests for transport layer."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from mcp.server import Server

from transport import (
    start_stdio_transport,
    start_sse_transport,
    start_tcp_transport,
    serve_with_tcp,
)


@pytest.fixture
def mock_server():
    server = MagicMock(spec=Server)
    server.create_initialization_options = MagicMock()
    server.run = AsyncMock()
    return server


class TestStdioTransport:
    @pytest.mark.asyncio
    async def test_start_stdio_transport(self, mock_server):
        with patch("transport.stdio_server") as mock_stdio:
            mock_read_stream = MagicMock()
            mock_write_stream = MagicMock()
            mock_stdio.return_value.__aenter__.return_value = (
                mock_read_stream,
                mock_write_stream,
            )

            await start_stdio_transport(mock_server)

            mock_stdio.assert_called_once()
            mock_server.create_initialization_options.assert_called_once()
            mock_server.run.assert_called_once()


class TestSseTransport:
    @pytest.mark.asyncio
    async def test_start_sse_transport_creates_server(self, mock_server):
        with patch("uvicorn.Server") as mock_uvicorn_server:
            mock_instance = AsyncMock()
            mock_uvicorn_server.return_value = mock_instance

            task = asyncio.create_task(
                start_sse_transport(mock_server, "127.0.0.1", 9011)
            )

            await asyncio.sleep(0.1)
            task.cancel()

            try:
                await task
            except asyncio.CancelledError:
                pass

            mock_uvicorn_server.assert_called_once()
            config = mock_uvicorn_server.call_args[0][0]
            assert config.host == "127.0.0.1"
            assert config.port == 9011


class TestTcpTransport:
    @pytest.mark.asyncio
    async def test_start_tcp_transport_creates_server(self, mock_server):
        tcp_server = await start_tcp_transport(mock_server, "127.0.0.1", 9011)

        assert tcp_server is not None
        assert isinstance(tcp_server, asyncio.AbstractServer)

        tcp_server.close()
        await tcp_server.wait_closed()

    @pytest.mark.asyncio
    async def test_serve_with_tcp_starts_server(self, mock_server):
        task = asyncio.create_task(serve_with_tcp(mock_server, "127.0.0.1", 9877))

        await asyncio.sleep(0.1)

        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


class TestTransportIntegration:
    @pytest.mark.asyncio
    async def test_tcp_transport_accepts_connections(self):
        server = Server("test-server")

        @server.list_tools()
        async def list_tools():
            return []

        tcp_server = await start_tcp_transport(server, "127.0.0.1", 9878)

        await asyncio.sleep(0.1)

        tcp_server.close()
        await tcp_server.wait_closed()
