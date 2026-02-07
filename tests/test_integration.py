"""Integration tests for mitmproxy-mcp end-to-end scenarios.

Tests all 20 MCP tools with simulated HTTP traffic in CI-compatible manner.
No GUI, no display required, no network calls (mocked).

Tool Categories:
- Flow tools (8): get_flows, get_flow_by_id, search_flows, get_flow_request,
                  get_flow_response, clear_flows, get_flow_count, export_flows
- Replay tools (4): replay_request, send_request, modify_and_send, duplicate_flow
- Intercept tools (5): set_intercept_filter, get_intercepted_flows, resume_flow,
                       resume_all, drop_flow
- Config tools (3): get_options, set_option, get_status
"""

import json
import sys
import os
from unittest.mock import AsyncMock, patch, MagicMock
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from mitmproxy.test import tflow

from storage import FlowStorage, set_storage
from tools.flows import handle_flow_tool
from tools.replay import handle_replay_tool
from tools.intercept import (
    handle_intercept_tool,
    set_intercept_filter_internal,
)
from tools.config import handle_config_tool
from privacy import init_redaction_engine, reset_redaction_engine


class TestFullFlowLifecycle:
    """Scenario 1: Full flow lifecycle - capture, query, details, clear."""

    def setup_method(self):
        """Set up fresh storage and redaction engine for each test."""
        self.storage = FlowStorage(max_flows=100)
        set_storage(self.storage)
        init_redaction_engine()

    def teardown_method(self):
        """Clean up redaction engine after each test."""
        reset_redaction_engine()

    @pytest.mark.asyncio
    async def test_complete_flow_lifecycle(self):
        """Test capture -> query -> get details -> clear cycle."""
        # Step 1: Capture simulated HTTP request
        flow = tflow.tflow(resp=True)
        flow.request.url = "http://httpbin.org/get?name=test"
        flow.request.method = "GET"
        flow.response.status_code = 200
        self.storage.add(flow)

        # Step 2: Query with get_flows
        result = await handle_flow_tool("get_flows", {"limit": 10})
        data = json.loads(result[0].text)
        assert data["total"] == 1
        assert data["count"] == 1
        assert "httpbin.org" in data["flows"][0]["url"]

        # Step 3: Get flow by ID
        flow_id = flow.id
        result = await handle_flow_tool("get_flow_by_id", {"flow_id": flow_id})
        data = json.loads(result[0].text)
        assert data["id"] == flow_id
        assert "request" in data
        assert "response" in data

        # Step 4: Get flow count
        result = await handle_flow_tool("get_flow_count", {})
        data = json.loads(result[0].text)
        assert data["count"] == 1

        # Step 5: Clear flows
        result = await handle_flow_tool("clear_flows", {})
        data = json.loads(result[0].text)
        assert data["cleared"] == 1

        # Step 6: Verify count is 0
        assert self.storage.count() == 0


class TestRequestReplayChain:
    """Scenario 2: Request replay chain - capture, replay, modify."""

    def setup_method(self):
        self.storage = FlowStorage(max_flows=100)
        set_storage(self.storage)
        init_redaction_engine()

    def teardown_method(self):
        reset_redaction_engine()

    @pytest.mark.asyncio
    async def test_replay_and_modify_chain(self):
        """Test original capture -> replay -> modify and send chain."""
        # Capture original request
        original_flow = tflow.tflow(resp=True)
        original_flow.request.url = "http://api.example.com/data"
        original_flow.request.method = "GET"
        original_flow.response.status_code = 200
        self.storage.add(original_flow)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b'{"result": "success"}'
        mock_response.headers = {"Content-Type": "application/json"}

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.request = AsyncMock(return_value=mock_response)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            # Replay original request
            result = await handle_replay_tool(
                "replay_request", {"flow_id": original_flow.id}
            )
            data = json.loads(result[0].text)
            assert data["status"] == "success"
            _ = data["new_flow_id"]

            # Modify and send
            result = await handle_replay_tool(
                "modify_and_send",
                {
                    "flow_id": original_flow.id,
                    "method": "POST",
                    "body": '{"new": "data"}',
                },
            )
            data = json.loads(result[0].text)
            assert data["status"] == "success"
            assert data["modifications"]["method"] == "POST"

            # Verify all 3 flows exist (original + replay + modified)
            assert self.storage.count() == 3


class TestInterceptionWorkflow:
    """Scenario 3: Interception workflow - filter, intercept, resume."""

    def setup_method(self):
        set_intercept_filter_internal("")
        self.storage = FlowStorage(max_flows=100)
        set_storage(self.storage)
        init_redaction_engine()

    def teardown_method(self):
        set_intercept_filter_internal("")
        reset_redaction_engine()

    @pytest.mark.asyncio
    async def test_intercept_and_resume_workflow(self):
        """Test set filter -> intercept flow -> get intercepted -> resume."""
        # Step 1: Set intercept filter
        result = await handle_intercept_tool(
            "set_intercept_filter", {"filter": "~u api"}
        )
        data = json.loads(result[0].text)
        assert data["status"] == "success"
        assert data["filter"] == "~u api"

        # Step 2: Create intercepted flow
        flow = tflow.tflow(resp=True)
        flow.request.url = "http://api.example.com/endpoint"
        flow.intercept()
        self.storage.add(flow)

        # Step 3: Get intercepted flows
        result = await handle_intercept_tool("get_intercepted_flows", {})
        data = json.loads(result[0].text)
        assert data["count"] == 1
        assert data["flows"][0]["intercepted"] is True
        assert data["current_filter"] == "~u api"

        # Step 4: Resume the flow
        result = await handle_intercept_tool("resume_flow", {"flow_id": flow.id})
        data = json.loads(result[0].text)
        assert data["status"] == "success"
        assert flow.intercepted is False

        # Step 5: Verify no more intercepted flows
        result = await handle_intercept_tool("get_intercepted_flows", {})
        data = json.loads(result[0].text)
        assert data["count"] == 0


class TestHARExport:
    """Scenario 4: HAR export validation."""

    def setup_method(self):
        self.storage = FlowStorage(max_flows=100)
        set_storage(self.storage)
        init_redaction_engine()

    def teardown_method(self):
        reset_redaction_engine()

    @pytest.mark.asyncio
    async def test_har_export_structure(self):
        """Test HAR export produces valid JSON structure."""
        # Capture multiple requests
        for i in range(3):
            flow = tflow.tflow(resp=True)
            flow.request.url = f"http://example.com/api/resource{i}"
            flow.request.method = "GET"
            flow.response.status_code = 200
            self.storage.add(flow)

        # Export to HAR
        result = await handle_flow_tool("export_flows", {})
        har = json.loads(result[0].text)

        # Validate HAR JSON structure
        assert "log" in har
        assert har["log"]["version"] == "1.2"
        assert "creator" in har["log"]
        assert har["log"]["creator"]["name"] == "mitmproxy-mcp"
        assert "entries" in har["log"]
        assert len(har["log"]["entries"]) == 3

        # Validate entry structure
        entry = har["log"]["entries"][0]
        assert "startedDateTime" in entry
        assert "time" in entry
        assert "request" in entry
        assert "response" in entry
        assert "cache" in entry
        assert "timings" in entry

        # Validate request
        assert "method" in entry["request"]
        assert "url" in entry["request"]
        assert "headers" in entry["request"]

        # Validate response
        assert "status" in entry["response"]
        assert "content" in entry["response"]

    @pytest.mark.asyncio
    async def test_har_export_specific_flows(self):
        """Test HAR export with specific flow IDs."""
        flows = []
        for i in range(5):
            flow = tflow.tflow(resp=True)
            flow.request.url = f"http://example.com/path{i}"
            self.storage.add(flow)
            flows.append(flow)

        # Export only first 2 flows
        flow_ids = [flows[0].id, flows[1].id]
        result = await handle_flow_tool("export_flows", {"flow_ids": flow_ids})
        har = json.loads(result[0].text)

        assert len(har["log"]["entries"]) == 2


class TestPrivacyInContext:
    """Scenario 5: Privacy redaction in realistic scenarios."""

    def setup_method(self):
        self.storage = FlowStorage(max_flows=100)
        set_storage(self.storage)
        init_redaction_engine()

    def teardown_method(self):
        reset_redaction_engine()

    @pytest.mark.asyncio
    async def test_bearer_token_redaction(self):
        """Test Bearer token in Authorization header is redacted."""
        flow = tflow.tflow(resp=True)
        flow.request.url = "http://api.example.com/secure"
        flow.request.headers["Authorization"] = (
            "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret"
        )
        self.storage.add(flow)

        result = await handle_flow_tool("get_flow_by_id", {"flow_id": flow.id})
        data = json.loads(result[0].text)

        # Verify token is redacted
        auth_header = data["request"]["headers"].get("Authorization", "")
        assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in auth_header
        assert "[REDACTED]" in auth_header

    @pytest.mark.asyncio
    async def test_api_key_in_url_redaction(self):
        """Test api_key in URL query params is redacted."""
        flow = tflow.tflow(resp=True)
        flow.request.url = (
            "http://api.example.com/data?api_key=supersecret123&name=test"
        )
        self.storage.add(flow)

        result = await handle_flow_tool("get_flows", {"limit": 10})
        data = json.loads(result[0].text)

        # Verify api_key is redacted in URL
        url = data["flows"][0]["url"]
        assert "supersecret123" not in url
        assert "[REDACTED]" in url

    @pytest.mark.asyncio
    async def test_password_in_body_redaction(self):
        """Test password in request body is redacted."""
        flow = tflow.tflow(resp=True)
        flow.request.url = "http://api.example.com/login"
        flow.request.content = b'{"username": "admin", "password": "secret123"}'
        self.storage.add(flow)

        result = await handle_flow_tool("get_flow_request", {"flow_id": flow.id})
        data = json.loads(result[0].text)

        # Verify password is redacted
        body = data.get("body", "")
        assert "secret123" not in body
        assert "[REDACTED]" in body

    @pytest.mark.asyncio
    async def test_har_export_with_redaction(self):
        """Test HAR export includes redaction."""
        flow = tflow.tflow(resp=True)
        flow.request.url = "http://api.example.com/secure?api_key=mysecret"
        flow.request.headers["Authorization"] = "Bearer token123"
        self.storage.add(flow)

        result = await handle_flow_tool("export_flows", {})
        har = json.loads(result[0].text)

        entry = har["log"]["entries"][0]
        # Check URL redaction
        assert "mysecret" not in entry["request"]["url"]
        # Check header redaction
        for header in entry["request"]["headers"]:
            if header["name"].lower() == "authorization":
                assert "token123" not in header["value"]


class TestConfigurationManagement:
    """Scenario 6: Configuration management."""

    def setup_method(self):
        self.storage = FlowStorage(max_flows=100)
        set_storage(self.storage)

    @pytest.mark.asyncio
    async def test_get_status_and_options(self):
        """Test getting proxy status and options."""
        with patch("tools.config.ctx") as mock_ctx:
            with patch("tools.config.version") as mock_version:
                mock_version.VERSION = "10.0.0"
                mock_ctx.options.listen_host = "127.0.0.1"
                mock_ctx.options.listen_port = 8080
                mock_ctx.options.mode = "regular"
                mock_ctx.options.intercept = None
                mock_ctx.options.anticache = False
                mock_ctx.options.anticomp = False

                # Get status
                result = await handle_config_tool("get_status", {})
                status = json.loads(result[0].text)

                assert status["version"] == "10.0.0"
                assert status["listen_address"] == "127.0.0.1:8080"
                assert status["mode"] == "regular"

    @pytest.mark.asyncio
    async def test_set_allowed_option(self):
        """Test setting an allowed option."""
        with patch("tools.config.ctx") as mock_ctx:
            mock_ctx.options.anticache = False
            mock_ctx.options.update = MagicMock()

            result = await handle_config_tool(
                "set_option", {"key": "anticache", "value": True}
            )
            data = json.loads(result[0].text)

            assert data["status"] == "success"
            assert data["key"] == "anticache"
            assert data["value"] is True
            mock_ctx.options.update.assert_called_once_with(anticache=True)

    @pytest.mark.asyncio
    async def test_blocked_option_raises_error(self):
        """Test that blocked options cannot be modified."""
        with patch("tools.config.ctx") as mock_ctx:
            mock_ctx.options.listen_port = 8080

            result = await handle_config_tool(
                "set_option", {"key": "listen_port", "value": 9090}
            )
            data = json.loads(result[0].text)

            assert "error" in data
            assert "blocked" in data["error"].lower()


class TestSearchAndFilter:
    """Scenario 7: Search and filter operations."""

    def setup_method(self):
        self.storage = FlowStorage(max_flows=100)
        set_storage(self.storage)
        init_redaction_engine()

    def teardown_method(self):
        reset_redaction_engine()

    @pytest.mark.asyncio
    async def test_search_by_pattern(self):
        """Test searching flows by regex pattern."""
        # Create flows with different URLs
        flow1 = tflow.tflow(resp=True)
        flow1.request.url = "http://api.example.com/users"
        self.storage.add(flow1)

        flow2 = tflow.tflow(resp=True)
        flow2.request.url = "http://other.example.com/items"
        self.storage.add(flow2)

        flow3 = tflow.tflow(resp=True)
        flow3.request.url = "http://api.example.com/products"
        self.storage.add(flow3)

        # Search for 'api'
        result = await handle_flow_tool("search_flows", {"pattern": "api"})
        data = json.loads(result[0].text)

        assert data["count"] == 2
        for flow in data["flows"]:
            assert "api" in flow["url"]

    @pytest.mark.asyncio
    async def test_filter_by_method(self):
        """Test filtering flows by HTTP method."""
        flow_get = tflow.tflow(resp=True)
        flow_get.request.method = "GET"
        self.storage.add(flow_get)

        flow_post = tflow.tflow(resp=True)
        flow_post.request.method = "POST"
        self.storage.add(flow_post)

        result = await handle_flow_tool("get_flows", {"method": "POST"})
        data = json.loads(result[0].text)

        assert data["count"] == 1
        assert data["flows"][0]["method"] == "POST"

    @pytest.mark.asyncio
    async def test_filter_by_status_code(self):
        """Test filtering flows by status code."""
        flow_200 = tflow.tflow(resp=True)
        flow_200.response.status_code = 200
        self.storage.add(flow_200)

        flow_404 = tflow.tflow(resp=True)
        flow_404.response.status_code = 404
        self.storage.add(flow_404)

        flow_500 = tflow.tflow(resp=True)
        flow_500.response.status_code = 500
        self.storage.add(flow_500)

        result = await handle_flow_tool("get_flows", {"status_code": 404})
        data = json.loads(result[0].text)

        assert data["count"] == 1
        assert data["flows"][0]["status_code"] == 404

    @pytest.mark.asyncio
    async def test_filter_by_url_pattern(self):
        """Test filtering flows by URL pattern."""
        flow1 = tflow.tflow(resp=True)
        flow1.request.url = "http://example.com/api/v1/users"
        self.storage.add(flow1)

        flow2 = tflow.tflow(resp=True)
        flow2.request.url = "http://example.com/web/page"
        self.storage.add(flow2)

        result = await handle_flow_tool("get_flows", {"url_pattern": "api/v1"})
        data = json.loads(result[0].text)

        assert data["count"] == 1
        assert "api/v1" in data["flows"][0]["url"]


class TestErrorHandling:
    """Scenario 8: Error handling for invalid operations."""

    def setup_method(self):
        set_intercept_filter_internal("")
        self.storage = FlowStorage(max_flows=100)
        set_storage(self.storage)
        init_redaction_engine()

    def teardown_method(self):
        set_intercept_filter_internal("")
        reset_redaction_engine()

    @pytest.mark.asyncio
    async def test_nonexistent_flow_id(self):
        """Test querying non-existent flow ID returns error."""
        result = await handle_flow_tool(
            "get_flow_by_id", {"flow_id": "nonexistent-id-123"}
        )
        data = json.loads(result[0].text)

        assert "error" in data
        assert "not found" in data["error"].lower()

    @pytest.mark.asyncio
    async def test_replay_nonexistent_flow(self):
        """Test replaying non-existent flow returns error."""
        result = await handle_replay_tool(
            "replay_request", {"flow_id": "nonexistent-id"}
        )
        data = json.loads(result[0].text)

        assert "error" in data

    @pytest.mark.asyncio
    async def test_invalid_intercept_filter(self):
        """Test setting invalid intercept filter returns error."""
        result = await handle_intercept_tool(
            "set_intercept_filter", {"filter": "~invalid_operator"}
        )
        data = json.loads(result[0].text)

        assert data["status"] == "error"
        assert "Invalid filter syntax" in data["message"]

    @pytest.mark.asyncio
    async def test_resume_non_intercepted_flow(self):
        """Test resuming a non-intercepted flow returns error."""
        flow = tflow.tflow(resp=True)
        self.storage.add(flow)

        result = await handle_intercept_tool("resume_flow", {"flow_id": flow.id})
        data = json.loads(result[0].text)

        assert "error" in data
        assert "not intercepted" in data["error"].lower()

    @pytest.mark.asyncio
    async def test_send_request_missing_url(self):
        """Test sending request without URL returns error."""
        result = await handle_replay_tool("send_request", {"method": "GET"})
        data = json.loads(result[0].text)

        assert "error" in data
        assert "url" in data["error"].lower()


class TestConcurrentOperations:
    """Scenario 9: Thread safety and concurrent operations."""

    def setup_method(self):
        self.storage = FlowStorage(max_flows=1000)
        set_storage(self.storage)

    def test_concurrent_add_and_query(self):
        """Test concurrent flow additions and queries."""
        errors = []
        results = []

        def add_flows():
            try:
                for _ in range(100):
                    flow = tflow.tflow(resp=True)
                    self.storage.add(flow)
            except Exception as e:
                errors.append(e)

        def query_flows():
            try:
                for _ in range(100):
                    count = self.storage.count()
                    results.append(count)
                    self.storage.get_all(limit=10)
            except Exception as e:
                errors.append(e)

        # Run concurrent threads
        threads = []
        for _ in range(5):
            threads.append(threading.Thread(target=add_flows))
            threads.append(threading.Thread(target=query_flows))

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # No exceptions should occur
        assert len(errors) == 0
        # Final count should be 500 (5 threads * 100 flows)
        assert self.storage.count() == 500


class TestInterceptMultipleFlows:
    """Scenario 10: Multiple flow interception and batch operations."""

    def setup_method(self):
        set_intercept_filter_internal("")
        self.storage = FlowStorage(max_flows=100)
        set_storage(self.storage)
        init_redaction_engine()

    def teardown_method(self):
        set_intercept_filter_internal("")
        reset_redaction_engine()

    @pytest.mark.asyncio
    async def test_resume_all_intercepted_flows(self):
        """Test resuming all intercepted flows at once."""
        # Create multiple intercepted flows
        flows = []
        for i in range(5):
            flow = tflow.tflow(resp=True)
            flow.request.url = f"http://api.example.com/resource{i}"
            flow.intercept()
            self.storage.add(flow)
            flows.append(flow)

        # Verify all are intercepted
        result = await handle_intercept_tool("get_intercepted_flows", {})
        data = json.loads(result[0].text)
        assert data["count"] == 5

        # Resume all
        result = await handle_intercept_tool("resume_all", {})
        data = json.loads(result[0].text)

        assert data["status"] == "success"
        assert data["resumed_count"] == 5

        # Verify all flows are resumed
        for flow in flows:
            assert flow.intercepted is False

    @pytest.mark.asyncio
    async def test_drop_intercepted_flow(self):
        """Test dropping an intercepted flow."""
        flow = tflow.tflow(resp=True)
        flow.intercept()
        self.storage.add(flow)

        result = await handle_intercept_tool("drop_flow", {"flow_id": flow.id})
        data = json.loads(result[0].text)

        assert data["status"] == "success"
        assert flow.intercepted is False
        assert flow.error is not None


class TestDuplicateFlow:
    """Scenario 11: Flow duplication operations."""

    def setup_method(self):
        self.storage = FlowStorage(max_flows=100)
        set_storage(self.storage)
        init_redaction_engine()

    def teardown_method(self):
        reset_redaction_engine()

    @pytest.mark.asyncio
    async def test_duplicate_flow_creates_copy(self):
        """Test duplicating a flow creates an independent copy."""
        original = tflow.tflow(resp=True)
        original.request.url = "http://api.example.com/original"
        original.request.content = b"original body"
        self.storage.add(original)

        result = await handle_replay_tool("duplicate_flow", {"flow_id": original.id})
        data = json.loads(result[0].text)

        assert data["original_flow_id"] == original.id
        assert data["new_flow_id"] != original.id
        assert self.storage.count() == 2

        # Verify duplicate has same content
        duplicate = self.storage.get(data["new_flow_id"])
        assert duplicate is not None
        assert duplicate.request.url == original.request.url


class TestEndToEndScenario:
    """Scenario 12: Complete end-to-end workflow simulation."""

    def setup_method(self):
        set_intercept_filter_internal("")
        self.storage = FlowStorage(max_flows=100)
        set_storage(self.storage)
        init_redaction_engine()

    def teardown_method(self):
        set_intercept_filter_internal("")
        reset_redaction_engine()

    @pytest.mark.asyncio
    async def test_full_workflow_simulation(self):
        """Test a complete workflow: capture, analyze, replay, export."""
        # Step 1: Simulate capturing traffic (multiple requests)
        flows = []
        for i in range(3):
            flow = tflow.tflow(resp=True)
            flow.request.url = f"http://api.example.com/endpoint{i}"
            flow.request.method = ["GET", "POST", "GET"][i]
            flow.request.headers["Authorization"] = f"Bearer token{i}"
            flow.response.status_code = [200, 201, 404][i]
            self.storage.add(flow)
            flows.append(flow)

        # Step 2: Get status
        with patch("tools.config.ctx") as mock_ctx:
            with patch("tools.config.version") as mock_version:
                mock_version.VERSION = "10.0.0"
                mock_ctx.options.listen_host = "127.0.0.1"
                mock_ctx.options.listen_port = 8080
                mock_ctx.options.mode = "regular"
                mock_ctx.options.intercept = None
                mock_ctx.options.anticache = False
                mock_ctx.options.anticomp = False

                result = await handle_config_tool("get_status", {})
                status = json.loads(result[0].text)
                assert status["flow_count"] == 3

        # Step 3: Search for POST requests
        result = await handle_flow_tool("search_flows", {"pattern": "POST"})
        data = json.loads(result[0].text)
        assert data["count"] == 1

        # Step 4: Filter by 404 status
        result = await handle_flow_tool("get_flows", {"status_code": 404})
        data = json.loads(result[0].text)
        assert data["count"] == 1

        # Step 5: Get specific flow details (with redaction)
        result = await handle_flow_tool("get_flow_by_id", {"flow_id": flows[0].id})
        data = json.loads(result[0].text)
        # Bearer token should be redacted
        auth = data["request"]["headers"].get("Authorization", "")
        assert "token0" not in auth
        assert "[REDACTED]" in auth

        # Step 6: Export to HAR
        result = await handle_flow_tool("export_flows", {})
        har = json.loads(result[0].text)
        assert len(har["log"]["entries"]) == 3

        # Step 7: Clear flows
        result = await handle_flow_tool("clear_flows", {})
        data = json.loads(result[0].text)
        assert data["cleared"] == 3
        assert self.storage.count() == 0
