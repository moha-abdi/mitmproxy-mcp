import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from mitmproxy.test import tflow

from storage import FlowStorage, set_storage
from tools.intercept import (
    INTERCEPT_TOOLS,
    handle_intercept_tool,
    set_intercept_filter_internal,
    get_intercept_filter,
    get_parsed_filter,
)


class TestInterceptToolDefinitions:
    def test_all_tools_defined(self):
        tool_names = {t.name for t in INTERCEPT_TOOLS}
        expected = {
            "set_intercept_filter",
            "get_intercepted_flows",
            "resume_flow",
            "resume_all",
            "drop_flow",
        }
        assert tool_names == expected

    def test_tools_have_descriptions(self):
        for tool in INTERCEPT_TOOLS:
            assert tool.description, f"{tool.name} missing description"
            assert tool.inputSchema, f"{tool.name} missing input schema"


class TestSetInterceptFilterInternal:
    def setup_method(self):
        set_intercept_filter_internal("")

    def test_set_valid_url_filter(self):
        result = set_intercept_filter_internal("~u httpbin")
        assert result["status"] == "success"
        assert result["filter"] == "~u httpbin"
        assert get_intercept_filter() == "~u httpbin"
        assert get_parsed_filter() is not None

    def test_set_valid_method_filter(self):
        result = set_intercept_filter_internal("~m POST")
        assert result["status"] == "success"
        assert result["filter"] == "~m POST"
        assert get_intercept_filter() == "~m POST"

    def test_set_combined_filter(self):
        result = set_intercept_filter_internal("~u api & ~m GET")
        assert result["status"] == "success"
        assert result["filter"] == "~u api & ~m GET"

    def test_clear_filter_with_empty_string(self):
        set_intercept_filter_internal("~u test")
        assert get_intercept_filter() == "~u test"

        result = set_intercept_filter_internal("")
        assert result["status"] == "success"
        assert result["message"] == "Interception disabled"
        assert get_intercept_filter() is None
        assert get_parsed_filter() is None

    def test_invalid_filter_syntax(self):
        result = set_intercept_filter_internal("~invalid_operator")
        assert result["status"] == "error"
        assert "Invalid filter syntax" in result["message"]


class TestSetInterceptFilterTool:
    def setup_method(self):
        set_intercept_filter_internal("")
        self.storage = FlowStorage(max_flows=100)
        set_storage(self.storage)

    @pytest.mark.asyncio
    async def test_set_filter_via_tool(self):
        result = await handle_intercept_tool(
            "set_intercept_filter", {"filter": "~u example"}
        )
        data = json.loads(result[0].text)

        assert data["status"] == "success"
        assert data["filter"] == "~u example"

    @pytest.mark.asyncio
    async def test_clear_filter_via_tool(self):
        set_intercept_filter_internal("~u test")

        result = await handle_intercept_tool("set_intercept_filter", {"filter": ""})
        data = json.loads(result[0].text)

        assert data["status"] == "success"
        assert data["message"] == "Interception disabled"


class TestGetInterceptedFlows:
    def setup_method(self):
        set_intercept_filter_internal("")
        self.storage = FlowStorage(max_flows=100)
        set_storage(self.storage)

    @pytest.mark.asyncio
    async def test_no_intercepted_flows(self):
        flow = tflow.tflow(resp=True)
        self.storage.add(flow)

        result = await handle_intercept_tool("get_intercepted_flows", {})
        data = json.loads(result[0].text)

        assert data["count"] == 0
        assert data["flows"] == []

    @pytest.mark.asyncio
    async def test_with_intercepted_flows(self):
        flow = tflow.tflow(resp=True)
        flow.intercept()
        self.storage.add(flow)

        result = await handle_intercept_tool("get_intercepted_flows", {})
        data = json.loads(result[0].text)

        assert data["count"] == 1
        assert len(data["flows"]) == 1
        assert data["flows"][0]["id"] == flow.id
        assert data["flows"][0]["intercepted"] is True

    @pytest.mark.asyncio
    async def test_includes_current_filter(self):
        set_intercept_filter_internal("~u api")

        result = await handle_intercept_tool("get_intercepted_flows", {})
        data = json.loads(result[0].text)

        assert data["current_filter"] == "~u api"


class TestResumeFlow:
    def setup_method(self):
        set_intercept_filter_internal("")
        self.storage = FlowStorage(max_flows=100)
        set_storage(self.storage)

    @pytest.mark.asyncio
    async def test_resume_intercepted_flow(self):
        flow = tflow.tflow(resp=True)
        flow.intercept()
        self.storage.add(flow)
        assert flow.intercepted is True

        result = await handle_intercept_tool("resume_flow", {"flow_id": flow.id})
        data = json.loads(result[0].text)

        assert data["status"] == "success"
        assert data["flow_id"] == flow.id
        assert data["message"] == "Flow resumed"
        assert flow.intercepted is False

    @pytest.mark.asyncio
    async def test_resume_flow_not_found(self):
        result = await handle_intercept_tool("resume_flow", {"flow_id": "nonexistent"})
        data = json.loads(result[0].text)

        assert "error" in data
        assert "not found" in data["error"].lower()

    @pytest.mark.asyncio
    async def test_resume_flow_not_intercepted(self):
        flow = tflow.tflow(resp=True)
        self.storage.add(flow)
        assert flow.intercepted is False

        result = await handle_intercept_tool("resume_flow", {"flow_id": flow.id})
        data = json.loads(result[0].text)

        assert "error" in data
        assert "not intercepted" in data["error"].lower()

    @pytest.mark.asyncio
    async def test_resume_flow_missing_id(self):
        result = await handle_intercept_tool("resume_flow", {})
        data = json.loads(result[0].text)

        assert "error" in data
        assert "required" in data["error"].lower()


class TestResumeAll:
    def setup_method(self):
        set_intercept_filter_internal("")
        self.storage = FlowStorage(max_flows=100)
        set_storage(self.storage)

    @pytest.mark.asyncio
    async def test_resume_all_with_no_intercepted(self):
        flow = tflow.tflow(resp=True)
        self.storage.add(flow)

        result = await handle_intercept_tool("resume_all", {})
        data = json.loads(result[0].text)

        assert data["status"] == "success"
        assert data["resumed_count"] == 0

    @pytest.mark.asyncio
    async def test_resume_all_multiple_flows(self):
        flow1 = tflow.tflow(resp=True)
        flow1.intercept()
        self.storage.add(flow1)

        flow2 = tflow.tflow(resp=True)
        flow2.intercept()
        self.storage.add(flow2)

        flow3 = tflow.tflow(resp=True)
        self.storage.add(flow3)

        assert flow1.intercepted is True
        assert flow2.intercepted is True
        assert flow3.intercepted is False

        result = await handle_intercept_tool("resume_all", {})
        data = json.loads(result[0].text)

        assert data["status"] == "success"
        assert data["resumed_count"] == 2
        assert len(data["resumed_flow_ids"]) == 2
        assert flow1.id in data["resumed_flow_ids"]
        assert flow2.id in data["resumed_flow_ids"]
        assert flow1.intercepted is False
        assert flow2.intercepted is False


class TestDropFlow:
    def setup_method(self):
        set_intercept_filter_internal("")
        self.storage = FlowStorage(max_flows=100)
        set_storage(self.storage)

    @pytest.mark.asyncio
    async def test_drop_intercepted_flow(self):
        flow = tflow.tflow(resp=True)
        flow.intercept()
        self.storage.add(flow)
        assert flow.intercepted is True

        result = await handle_intercept_tool("drop_flow", {"flow_id": flow.id})
        data = json.loads(result[0].text)

        assert data["status"] == "success"
        assert data["flow_id"] == flow.id
        assert "dropped" in data["message"].lower()
        assert flow.intercepted is False
        assert flow.error is not None

    @pytest.mark.asyncio
    async def test_drop_flow_not_found(self):
        result = await handle_intercept_tool("drop_flow", {"flow_id": "nonexistent"})
        data = json.loads(result[0].text)

        assert "error" in data
        assert "not found" in data["error"].lower()

    @pytest.mark.asyncio
    async def test_drop_flow_not_intercepted(self):
        flow = tflow.tflow(resp=True)
        self.storage.add(flow)
        assert flow.intercepted is False

        result = await handle_intercept_tool("drop_flow", {"flow_id": flow.id})
        data = json.loads(result[0].text)

        assert "error" in data
        assert "not intercepted" in data["error"].lower()

    @pytest.mark.asyncio
    async def test_drop_flow_missing_id(self):
        result = await handle_intercept_tool("drop_flow", {})
        data = json.loads(result[0].text)

        assert "error" in data
        assert "required" in data["error"].lower()


class TestUnknownTool:
    def setup_method(self):
        self.storage = FlowStorage(max_flows=100)
        set_storage(self.storage)

    @pytest.mark.asyncio
    async def test_unknown_tool_returns_error(self):
        result = await handle_intercept_tool("nonexistent_tool", {})
        data = json.loads(result[0].text)

        assert "error" in data
        assert "Unknown tool" in data["error"]


class TestInterceptFlowSummary:
    def setup_method(self):
        set_intercept_filter_internal("")
        self.storage = FlowStorage(max_flows=100)
        set_storage(self.storage)

    @pytest.mark.asyncio
    async def test_flow_summary_structure(self):
        flow = tflow.tflow(resp=True)
        flow.intercept()
        self.storage.add(flow)

        result = await handle_intercept_tool("get_intercepted_flows", {})
        data = json.loads(result[0].text)

        summary = data["flows"][0]
        assert "id" in summary
        assert "method" in summary
        assert "url" in summary
        assert "status_code" in summary
        assert "timestamp" in summary
        assert "intercepted" in summary
