import json
import sys
import os
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from mitmproxy.test import tflow

from storage import FlowStorage, set_storage
from tools.config import (
    CONFIG_TOOLS,
    handle_config_tool,
)


class TestConfigToolDefinitions:
    def test_all_tools_defined(self):
        tool_names = {t.name for t in CONFIG_TOOLS}
        expected = {
            "get_options",
            "set_option",
            "get_status",
        }
        assert tool_names == expected

    def test_tools_have_descriptions(self):
        for tool in CONFIG_TOOLS:
            assert tool.description, f"{tool.name} missing description"
            assert tool.inputSchema, f"{tool.name} missing input schema"

    def test_get_options_schema(self):
        tool = next(t for t in CONFIG_TOOLS if t.name == "get_options")
        assert "keys" in tool.inputSchema["properties"]
        assert tool.inputSchema["properties"]["keys"]["type"] == "array"

    def test_set_option_schema(self):
        tool = next(t for t in CONFIG_TOOLS if t.name == "set_option")
        assert "key" in tool.inputSchema["properties"]
        assert "value" in tool.inputSchema["properties"]
        assert "key" in tool.inputSchema["required"]
        assert "value" in tool.inputSchema["required"]

    def test_get_status_schema(self):
        tool = next(t for t in CONFIG_TOOLS if t.name == "get_status")
        assert tool.inputSchema["properties"] == {}


class TestGetOptions:
    def setup_method(self):
        self.storage = FlowStorage(max_flows=100)
        set_storage(self.storage)

    @pytest.mark.asyncio
    async def test_get_default_curated_options(self):
        with patch("tools.config.ctx") as mock_ctx:
            mock_ctx.options.listen_host = "127.0.0.1"
            mock_ctx.options.listen_port = 8080
            mock_ctx.options.mode = "regular"
            mock_ctx.options.intercept = None
            mock_ctx.options.flow_detail = 2
            mock_ctx.options.ssl_insecure = False
            mock_ctx.options.anticache = False
            mock_ctx.options.anticomp = False
            mock_ctx.options.showhost = False

            result = await handle_config_tool("get_options", {})
            data = json.loads(result[0].text)

            assert "listen_host" in data
            assert data["listen_host"] == "127.0.0.1"
            assert data["listen_port"] == 8080
            assert data["mode"] == "regular"

    @pytest.mark.asyncio
    async def test_get_specific_keys(self):
        with patch("tools.config.ctx") as mock_ctx:
            mock_ctx.options.listen_host = "127.0.0.1"
            mock_ctx.options.listen_port = 8080
            mock_ctx.options.anticache = True

            result = await handle_config_tool(
                "get_options", {"keys": ["listen_host", "anticache"]}
            )
            data = json.loads(result[0].text)

            assert "listen_host" in data
            assert "anticache" in data
            assert data["listen_host"] == "127.0.0.1"
            assert data["anticache"] is True
            assert "listen_port" not in data

    @pytest.mark.asyncio
    async def test_get_nonexistent_key(self):
        with patch("tools.config.ctx") as mock_ctx:
            mock_ctx.options.listen_host = "127.0.0.1"
            mock_ctx.options.nonexistent_option = None

            result = await handle_config_tool(
                "get_options", {"keys": ["listen_host", "nonexistent_option"]}
            )
            data = json.loads(result[0].text)

            assert data["listen_host"] == "127.0.0.1"
            assert data["nonexistent_option"] is None

    @pytest.mark.asyncio
    async def test_get_empty_keys_list(self):
        with patch("tools.config.ctx") as mock_ctx:
            mock_ctx.options.listen_host = "127.0.0.1"
            mock_ctx.options.listen_port = 8080
            mock_ctx.options.mode = "regular"
            mock_ctx.options.intercept = None
            mock_ctx.options.flow_detail = 2
            mock_ctx.options.ssl_insecure = False
            mock_ctx.options.anticache = False
            mock_ctx.options.anticomp = False
            mock_ctx.options.showhost = False

            result = await handle_config_tool("get_options", {"keys": []})
            data = json.loads(result[0].text)

            assert isinstance(data, dict)
            assert len(data) == 0


class TestSetOption:
    def setup_method(self):
        self.storage = FlowStorage(max_flows=100)
        set_storage(self.storage)

    @pytest.mark.asyncio
    async def test_set_valid_option(self):
        with patch("tools.config.ctx") as mock_ctx:
            mock_ctx.options.anticache = False
            mock_ctx.options.update = Mock()

            result = await handle_config_tool(
                "set_option", {"key": "anticache", "value": True}
            )
            data = json.loads(result[0].text)

            assert data["status"] == "success"
            assert data["key"] == "anticache"
            assert data["value"] is True
            mock_ctx.options.update.assert_called_once_with(anticache=True)

    @pytest.mark.asyncio
    async def test_set_blocked_option_listen_host(self):
        with patch("tools.config.ctx") as mock_ctx:
            mock_ctx.options.listen_host = "127.0.0.1"

            result = await handle_config_tool(
                "set_option", {"key": "listen_host", "value": "0.0.0.0"}
            )
            data = json.loads(result[0].text)

            assert "error" in data
            assert "blocked" in data["error"].lower()
            assert "listen_host" in data["blocked_options"]

    @pytest.mark.asyncio
    async def test_set_blocked_option_listen_port(self):
        with patch("tools.config.ctx") as mock_ctx:
            mock_ctx.options.listen_port = 8080

            result = await handle_config_tool(
                "set_option", {"key": "listen_port", "value": 9090}
            )
            data = json.loads(result[0].text)

            assert "error" in data
            assert "blocked" in data["error"].lower()

    @pytest.mark.asyncio
    async def test_set_blocked_option_mode(self):
        with patch("tools.config.ctx") as mock_ctx:
            mock_ctx.options.mode = "regular"

            result = await handle_config_tool(
                "set_option", {"key": "mode", "value": "transparent"}
            )
            data = json.loads(result[0].text)

            assert "error" in data
            assert "blocked" in data["error"].lower()

    @pytest.mark.asyncio
    async def test_set_blocked_option_ssl_insecure(self):
        with patch("tools.config.ctx") as mock_ctx:
            mock_ctx.options.ssl_insecure = False

            result = await handle_config_tool(
                "set_option", {"key": "ssl_insecure", "value": True}
            )
            data = json.loads(result[0].text)

            assert "error" in data
            assert "blocked" in data["error"].lower()

    @pytest.mark.asyncio
    async def test_set_nonexistent_option(self):
        with patch("tools.config.ctx") as mock_ctx:
            mock_options = Mock()
            mock_options.anticache = False

            mock_ctx.options = mock_options

            def hasattr_side_effect(obj, name):
                if obj is mock_ctx.options and name == "nonexistent_option":
                    return False
                return hasattr(type(obj), name)

            with patch("builtins.hasattr", side_effect=hasattr_side_effect):
                result = await handle_config_tool(
                    "set_option", {"key": "nonexistent_option", "value": True}
                )
                data = json.loads(result[0].text)

                assert "error" in data
                assert "does not exist" in data["error"]

    @pytest.mark.asyncio
    async def test_set_option_missing_key(self):
        result = await handle_config_tool("set_option", {"value": True})
        data = json.loads(result[0].text)

        assert "error" in data
        assert "key is required" in data["error"]

    @pytest.mark.asyncio
    async def test_set_option_update_exception(self):
        with patch("tools.config.ctx") as mock_ctx:
            mock_ctx.options.anticache = False
            mock_ctx.options.update = Mock(side_effect=ValueError("Invalid value"))

            result = await handle_config_tool(
                "set_option", {"key": "anticache", "value": "invalid"}
            )
            data = json.loads(result[0].text)

            assert "error" in data
            assert "Failed to set option" in data["error"]


class TestGetStatus:
    def setup_method(self):
        self.storage = FlowStorage(max_flows=100)
        set_storage(self.storage)

    @pytest.mark.asyncio
    async def test_get_status_basic(self):
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
                data = json.loads(result[0].text)

                assert data["version"] == "10.0.0"
                assert data["listen_address"] == "127.0.0.1:8080"
                assert data["mode"] == "regular"
                assert data["flow_count"] == 0

    @pytest.mark.asyncio
    async def test_get_status_with_flows(self):
        flow = tflow.tflow(resp=True)
        self.storage.add(flow)

        with patch("tools.config.ctx") as mock_ctx:
            with patch("tools.config.version") as mock_version:
                mock_version.VERSION = "10.0.0"
                mock_ctx.options.listen_host = "127.0.0.1"
                mock_ctx.options.listen_port = 8080
                mock_ctx.options.mode = "regular"
                mock_ctx.options.intercept = "~u api"
                mock_ctx.options.anticache = True
                mock_ctx.options.anticomp = True

                result = await handle_config_tool("get_status", {})
                data = json.loads(result[0].text)

                assert data["flow_count"] == 1
                assert data["intercept_filter"] == "~u api"
                assert data["anticache"] is True
                assert data["anticomp"] is True

    @pytest.mark.asyncio
    async def test_get_status_includes_all_fields(self):
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
                data = json.loads(result[0].text)

                required_fields = [
                    "version",
                    "listen_address",
                    "mode",
                    "flow_count",
                    "intercept_filter",
                    "anticache",
                    "anticomp",
                ]
                for field in required_fields:
                    assert field in data, f"Missing field: {field}"


class TestUnknownTool:
    @pytest.mark.asyncio
    async def test_unknown_tool_name(self):
        result = await handle_config_tool("unknown_tool", {})
        data = json.loads(result[0].text)

        assert "error" in data
        assert "Unknown tool" in data["error"]
