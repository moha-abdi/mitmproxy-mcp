import json

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from mitmproxy.test import tflow

from mitmproxy_mcp.storage import FlowStorage, set_storage
from mitmproxy_mcp.tools.replay import (
    handle_replay_tool,
    REPLAY_TOOLS,
    _create_flow_from_params,
    _duplicate_flow,
)


class TestReplayToolDefinitions:
    def test_all_tools_defined(self):
        tool_names = {t.name for t in REPLAY_TOOLS}
        expected = {
            "replay_request",
            "send_request",
            "modify_and_send",
            "duplicate_flow",
        }
        assert tool_names == expected

    def test_tools_have_descriptions(self):
        for tool in REPLAY_TOOLS:
            assert tool.description, f"{tool.name} missing description"
            assert tool.inputSchema, f"{tool.name} missing input schema"


class TestCreateFlowFromParams:
    def test_create_basic_get_request(self):
        flow = _create_flow_from_params(
            method="GET",
            url="http://example.com/api/test",
        )

        assert flow.request.method == "GET"
        assert flow.request.url == "http://example.com/api/test"
        assert flow.id is not None
        assert "Host" in flow.request.headers

    def test_create_post_with_body(self):
        flow = _create_flow_from_params(
            method="POST",
            url="http://example.com/api/data",
            body='{"key": "value"}',
        )

        assert flow.request.method == "POST"
        assert flow.request.content == b'{"key": "value"}'

    def test_create_with_custom_headers(self):
        flow = _create_flow_from_params(
            method="GET",
            url="http://example.com/api",
            headers={"Authorization": "Bearer token123", "X-Custom": "value"},
        )

        assert "Authorization" in flow.request.headers
        assert "X-Custom" in flow.request.headers


class TestDuplicateFlow:
    def test_duplicate_flow_basic(self):
        original = tflow.tflow(resp=True)
        duplicate = _duplicate_flow(original)

        assert duplicate.id != original.id
        assert duplicate.request.method == original.request.method
        assert duplicate.request.url == original.request.url

    def test_duplicate_preserves_request_content(self):
        original = tflow.tflow(resp=True)
        original.request.content = b"test body content"
        duplicate = _duplicate_flow(original)

        assert duplicate.request.content == b"test body content"

    def test_duplicate_preserves_response(self):
        original = tflow.tflow(resp=True)
        duplicate = _duplicate_flow(original)

        assert duplicate.response is not None
        assert duplicate.response.status_code == original.response.status_code

    def test_duplicate_without_response(self):
        original = tflow.tflow(resp=False)
        duplicate = _duplicate_flow(original)

        assert duplicate.response is None


class TestDuplicateFlowTool:
    def setup_method(self):
        self.storage = FlowStorage(max_flows=100)
        set_storage(self.storage)

    @pytest.mark.asyncio
    async def test_duplicate_flow_success(self):
        flow = tflow.tflow(resp=True)
        self.storage.add(flow)

        result = await handle_replay_tool("duplicate_flow", {"flow_id": flow.id})
        data = json.loads(result[0].text)

        assert data["original_flow_id"] == flow.id
        assert data["new_flow_id"] != flow.id
        assert "flow" in data
        assert self.storage.count() == 2

    @pytest.mark.asyncio
    async def test_duplicate_flow_not_found(self):
        result = await handle_replay_tool("duplicate_flow", {"flow_id": "nonexistent"})
        data = json.loads(result[0].text)

        assert "error" in data
        assert "not found" in data["error"].lower()

    @pytest.mark.asyncio
    async def test_duplicate_flow_missing_id(self):
        result = await handle_replay_tool("duplicate_flow", {})
        data = json.loads(result[0].text)

        assert "error" in data
        assert "required" in data["error"].lower()


class TestReplayRequestTool:
    def setup_method(self):
        self.storage = FlowStorage(max_flows=100)
        set_storage(self.storage)

    @pytest.mark.asyncio
    async def test_replay_request_not_found(self):
        result = await handle_replay_tool("replay_request", {"flow_id": "nonexistent"})
        data = json.loads(result[0].text)

        assert "error" in data

    @pytest.mark.asyncio
    async def test_replay_request_missing_id(self):
        result = await handle_replay_tool("replay_request", {})
        data = json.loads(result[0].text)

        assert "error" in data
        assert "required" in data["error"].lower()

    @pytest.mark.asyncio
    async def test_replay_request_success(self):
        flow = tflow.tflow(resp=True)
        flow.request.url = "http://httpbin.org/get"
        self.storage.add(flow)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b'{"success": true}'
        mock_response.headers = {"Content-Type": "application/json"}

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.request = AsyncMock(return_value=mock_response)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            result = await handle_replay_tool("replay_request", {"flow_id": flow.id})
            data = json.loads(result[0].text)

            assert data["original_flow_id"] == flow.id
            assert data["new_flow_id"] != flow.id
            assert data["status"] == "success"
            assert data["status_code"] == 200
            assert self.storage.count() == 2


class TestSendRequestTool:
    def setup_method(self):
        self.storage = FlowStorage(max_flows=100)
        set_storage(self.storage)

    @pytest.mark.asyncio
    async def test_send_request_missing_url(self):
        result = await handle_replay_tool("send_request", {})
        data = json.loads(result[0].text)

        assert "error" in data
        assert "url" in data["error"].lower()

    @pytest.mark.asyncio
    async def test_send_request_success(self):
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.content = b'{"id": 123}'
        mock_response.headers = {"Content-Type": "application/json"}

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.request = AsyncMock(return_value=mock_response)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            result = await handle_replay_tool(
                "send_request",
                {
                    "method": "POST",
                    "url": "http://httpbin.org/post",
                    "headers": {"Content-Type": "application/json"},
                    "body": '{"test": "data"}',
                },
            )
            data = json.loads(result[0].text)

            assert "flow_id" in data
            assert data["method"] == "POST"
            assert data["url"] == "http://httpbin.org/post"
            assert data["status"] == "success"
            assert data["status_code"] == 201
            assert self.storage.count() == 1

    @pytest.mark.asyncio
    async def test_send_request_default_method(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b""
        mock_response.headers = {}

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.request = AsyncMock(return_value=mock_response)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            result = await handle_replay_tool(
                "send_request",
                {"url": "http://example.com/test"},
            )
            data = json.loads(result[0].text)

            assert data["method"] == "GET"


class TestModifyAndSendTool:
    def setup_method(self):
        self.storage = FlowStorage(max_flows=100)
        set_storage(self.storage)

    @pytest.mark.asyncio
    async def test_modify_and_send_not_found(self):
        result = await handle_replay_tool("modify_and_send", {"flow_id": "nonexistent"})
        data = json.loads(result[0].text)

        assert "error" in data

    @pytest.mark.asyncio
    async def test_modify_and_send_missing_id(self):
        result = await handle_replay_tool("modify_and_send", {})
        data = json.loads(result[0].text)

        assert "error" in data
        assert "required" in data["error"].lower()

    @pytest.mark.asyncio
    async def test_modify_and_send_change_method(self):
        flow = tflow.tflow(resp=True)
        flow.request.method = "GET"
        flow.request.url = "http://example.com/api"
        self.storage.add(flow)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b""
        mock_response.headers = {}

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.request = AsyncMock(return_value=mock_response)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            result = await handle_replay_tool(
                "modify_and_send",
                {"flow_id": flow.id, "method": "POST"},
            )
            data = json.loads(result[0].text)

            assert data["modifications"]["method"] == "POST"
            assert data["status"] == "success"

    @pytest.mark.asyncio
    async def test_modify_and_send_add_headers(self):
        flow = tflow.tflow(resp=True)
        self.storage.add(flow)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b""
        mock_response.headers = {}

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.request = AsyncMock(return_value=mock_response)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            result = await handle_replay_tool(
                "modify_and_send",
                {
                    "flow_id": flow.id,
                    "headers": {"X-Test-Header": "test-value"},
                },
            )
            data = json.loads(result[0].text)

            assert "X-Test-Header" in data["modifications"]["headers_added"]

    @pytest.mark.asyncio
    async def test_modify_and_send_remove_headers(self):
        flow = tflow.tflow(resp=True)
        flow.request.headers["X-Remove-Me"] = "value"
        self.storage.add(flow)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b""
        mock_response.headers = {}

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.request = AsyncMock(return_value=mock_response)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            result = await handle_replay_tool(
                "modify_and_send",
                {
                    "flow_id": flow.id,
                    "remove_headers": ["X-Remove-Me"],
                },
            )
            data = json.loads(result[0].text)

            assert "X-Remove-Me" in data["modifications"]["headers_removed"]

    @pytest.mark.asyncio
    async def test_modify_and_send_change_body(self):
        flow = tflow.tflow(resp=True)
        flow.request.content = b"original body"
        self.storage.add(flow)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b""
        mock_response.headers = {}

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.request = AsyncMock(return_value=mock_response)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            result = await handle_replay_tool(
                "modify_and_send",
                {
                    "flow_id": flow.id,
                    "body": "new body content",
                },
            )
            data = json.loads(result[0].text)

            assert data["modifications"]["body_modified"] is True


class TestUnknownTool:
    def setup_method(self):
        self.storage = FlowStorage(max_flows=100)
        set_storage(self.storage)

    @pytest.mark.asyncio
    async def test_unknown_tool_returns_error(self):
        result = await handle_replay_tool("nonexistent_tool", {})
        data = json.loads(result[0].text)

        assert "error" in data
        assert "Unknown tool" in data["error"]


class TestNetworkErrors:
    def setup_method(self):
        self.storage = FlowStorage(max_flows=100)
        set_storage(self.storage)

    @pytest.mark.asyncio
    async def test_send_request_network_error(self):
        import httpx

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.request = AsyncMock(
                side_effect=httpx.RequestError("Connection refused")
            )
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            result = await handle_replay_tool(
                "send_request",
                {"url": "http://unreachable.example.com"},
            )
            data = json.loads(result[0].text)

            assert data["status"] == "error"
            assert data["error"] is not None
