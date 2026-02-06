import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from mitmproxy.test import tflow

from storage import FlowStorage, set_storage
from tools.flows import handle_flow_tool, FLOW_TOOLS


class TestFlowStorage:
    def setup_method(self):
        self.storage = FlowStorage(max_flows=10)
        set_storage(self.storage)

    def test_add_and_get_flow(self):
        flow = tflow.tflow(resp=True)
        self.storage.add(flow)

        retrieved = self.storage.get(flow.id)
        assert retrieved is not None
        assert retrieved.id == flow.id

    def test_flow_not_found(self):
        result = self.storage.get("nonexistent-id")
        assert result is None

    def test_count(self):
        assert self.storage.count() == 0

        for _ in range(5):
            self.storage.add(tflow.tflow(resp=True))

        assert self.storage.count() == 5

    def test_clear(self):
        for _ in range(5):
            self.storage.add(tflow.tflow(resp=True))

        cleared = self.storage.clear()
        assert cleared == 5
        assert self.storage.count() == 0

    def test_fifo_eviction(self):
        storage = FlowStorage(max_flows=3)
        flows = [tflow.tflow(resp=True) for _ in range(5)]

        for f in flows:
            storage.add(f)

        assert storage.count() == 3
        assert storage.get(flows[0].id) is None
        assert storage.get(flows[1].id) is None
        assert storage.get(flows[2].id) is not None
        assert storage.get(flows[3].id) is not None
        assert storage.get(flows[4].id) is not None

    def test_update_existing_flow(self):
        flow = tflow.tflow(resp=False)
        self.storage.add(flow)

        flow.response = tflow.tresp()
        self.storage.add(flow)

        assert self.storage.count() == 1
        retrieved = self.storage.get(flow.id)
        assert retrieved.response is not None

    def test_get_all_pagination(self):
        for _ in range(10):
            self.storage.add(tflow.tflow(resp=True))

        first_page = self.storage.get_all(offset=0, limit=3)
        assert len(first_page) == 3

        second_page = self.storage.get_all(offset=3, limit=3)
        assert len(second_page) == 3

        all_flows = self.storage.get_all(offset=0, limit=100)
        assert len(all_flows) == 10

    def test_filter_by_method(self):
        get_flow = tflow.tflow(req=tflow.treq(method="GET"), resp=True)
        post_flow = tflow.tflow(req=tflow.treq(method="POST"), resp=True)
        self.storage.add(get_flow)
        self.storage.add(post_flow)

        get_flows = self.storage.get_all(method="GET")
        assert len(get_flows) == 1
        assert get_flows[0].request.method == "GET"

    def test_filter_by_url_pattern(self):
        flow1 = tflow.tflow(resp=True)
        flow1.request.url = "http://example.com/api/users"
        self.storage.add(flow1)

        flow2 = tflow.tflow(resp=True)
        flow2.request.url = "http://other.com/api/items"
        self.storage.add(flow2)

        results = self.storage.get_all(url_pattern="example")
        assert len(results) == 1
        assert "example" in results[0].request.url

    def test_search(self):
        flow1 = tflow.tflow(resp=True)
        flow1.request.url = "http://httpbin.org/get"
        self.storage.add(flow1)

        flow2 = tflow.tflow(resp=True)
        flow2.request.url = "http://example.com/post"
        self.storage.add(flow2)

        results = self.storage.search("httpbin")
        assert len(results) == 1
        assert "httpbin" in results[0].request.url


class TestFlowTools:
    def setup_method(self):
        self.storage = FlowStorage(max_flows=100)
        set_storage(self.storage)

        for i in range(3):
            flow = tflow.tflow(resp=True)
            flow.request.url = f"http://test{i}.example.com/path"
            self.storage.add(flow)

    @pytest.mark.asyncio
    async def test_get_flows_tool(self):
        result = await handle_flow_tool("get_flows", {})
        assert len(result) == 1

        data = json.loads(result[0].text)
        assert data["total"] == 3
        assert data["count"] == 3
        assert len(data["flows"]) == 3

    @pytest.mark.asyncio
    async def test_get_flows_pagination(self):
        result = await handle_flow_tool("get_flows", {"offset": 1, "limit": 1})
        data = json.loads(result[0].text)

        assert data["total"] == 3
        assert data["count"] == 1
        assert data["offset"] == 1

    @pytest.mark.asyncio
    async def test_get_flow_by_id(self):
        flows = self.storage.get_all(limit=1)
        flow_id = flows[0].id

        result = await handle_flow_tool("get_flow_by_id", {"flow_id": flow_id})
        data = json.loads(result[0].text)

        assert data["id"] == flow_id
        assert "request" in data
        assert "response" in data

    @pytest.mark.asyncio
    async def test_get_flow_by_id_not_found(self):
        result = await handle_flow_tool("get_flow_by_id", {"flow_id": "nonexistent"})
        data = json.loads(result[0].text)
        assert "error" in data

    @pytest.mark.asyncio
    async def test_search_flows(self):
        result = await handle_flow_tool("search_flows", {"pattern": "test1"})
        data = json.loads(result[0].text)

        assert data["count"] == 1
        assert "test1" in data["flows"][0]["url"]

    @pytest.mark.asyncio
    async def test_get_flow_request(self):
        flows = self.storage.get_all(limit=1)
        flow_id = flows[0].id

        result = await handle_flow_tool("get_flow_request", {"flow_id": flow_id})
        data = json.loads(result[0].text)

        assert "method" in data
        assert "url" in data
        assert "headers" in data

    @pytest.mark.asyncio
    async def test_get_flow_response(self):
        flows = self.storage.get_all(limit=1)
        flow_id = flows[0].id

        result = await handle_flow_tool("get_flow_response", {"flow_id": flow_id})
        data = json.loads(result[0].text)

        assert "status_code" in data
        assert "headers" in data

    @pytest.mark.asyncio
    async def test_get_flow_response_no_response(self):
        flow = tflow.tflow(resp=False)
        self.storage.add(flow)

        result = await handle_flow_tool("get_flow_response", {"flow_id": flow.id})
        data = json.loads(result[0].text)
        assert "error" in data

    @pytest.mark.asyncio
    async def test_clear_flows(self):
        assert self.storage.count() == 3

        result = await handle_flow_tool("clear_flows", {})
        data = json.loads(result[0].text)

        assert data["cleared"] == 3
        assert self.storage.count() == 0

    @pytest.mark.asyncio
    async def test_get_flow_count(self):
        result = await handle_flow_tool("get_flow_count", {})
        data = json.loads(result[0].text)

        assert data["count"] == 3
        assert data["max_flows"] == 100

    @pytest.mark.asyncio
    async def test_export_flows_har(self):
        result = await handle_flow_tool("export_flows", {})
        data = json.loads(result[0].text)

        assert "log" in data
        assert data["log"]["version"] == "1.2"
        assert "creator" in data["log"]
        assert "entries" in data["log"]
        assert len(data["log"]["entries"]) == 3

    @pytest.mark.asyncio
    async def test_export_flows_har_specific_ids(self):
        flows = self.storage.get_all(limit=2)
        flow_ids = [f.id for f in flows]

        result = await handle_flow_tool("export_flows", {"flow_ids": flow_ids})
        data = json.loads(result[0].text)

        assert len(data["log"]["entries"]) == 2

    @pytest.mark.asyncio
    async def test_har_entry_structure(self):
        result = await handle_flow_tool("export_flows", {})
        data = json.loads(result[0].text)
        entry = data["log"]["entries"][0]

        assert "startedDateTime" in entry
        assert "time" in entry
        assert "request" in entry
        assert "response" in entry
        assert "cache" in entry
        assert "timings" in entry

        assert "method" in entry["request"]
        assert "url" in entry["request"]
        assert "headers" in entry["request"]

        assert "status" in entry["response"]
        assert "content" in entry["response"]
        assert "headers" in entry["response"]


class TestToolDefinitions:
    def test_all_tools_defined(self):
        tool_names = {t.name for t in FLOW_TOOLS}
        expected = {
            "get_flows",
            "get_flow_by_id",
            "search_flows",
            "get_flow_request",
            "get_flow_response",
            "clear_flows",
            "get_flow_count",
            "export_flows",
        }
        assert tool_names == expected

    def test_tools_have_descriptions(self):
        for tool in FLOW_TOOLS:
            assert tool.description, f"{tool.name} missing description"
            assert tool.inputSchema, f"{tool.name} missing input schema"


class TestThreadSafety:
    def test_concurrent_adds(self):
        import threading

        storage = FlowStorage(max_flows=1000)

        def add_flows():
            for _ in range(100):
                storage.add(tflow.tflow(resp=True))

        threads = [threading.Thread(target=add_flows) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert storage.count() == 1000

    def test_concurrent_read_write(self):
        import threading

        storage = FlowStorage(max_flows=100)
        errors = []

        def writer():
            try:
                for _ in range(50):
                    storage.add(tflow.tflow(resp=True))
            except Exception as e:
                errors.append(e)

        def reader():
            try:
                for _ in range(50):
                    storage.get_all()
                    storage.count()
            except Exception as e:
                errors.append(e)

        threads = []
        for _ in range(5):
            threads.append(threading.Thread(target=writer))
            threads.append(threading.Thread(target=reader))

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
