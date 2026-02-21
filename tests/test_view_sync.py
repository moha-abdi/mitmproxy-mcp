from unittest.mock import patch

import pytest
from mitmproxy import exceptions

from mitmproxy_mcp.addon import MCPAddon
from mitmproxy_mcp.view_sync import parse_view_sync_actions, should_sync_action


def test_parse_all_actions():
    assert parse_view_sync_actions("all") == {"replay", "clear"}


def test_parse_none_actions():
    assert parse_view_sync_actions("none") == set()


def test_parse_subset_actions():
    assert parse_view_sync_actions("replay") == {"replay"}
    assert parse_view_sync_actions("clear,replay") == {"replay", "clear"}


@pytest.mark.parametrize(
    "raw_value",
    [
        "",
        "unknown",
        "replay,unknown",
        "all,replay",
        "none,clear",
        "replay,,clear",
    ],
)
def test_parse_invalid_values(raw_value: str):
    with pytest.raises(ValueError):
        parse_view_sync_actions(raw_value)


def test_should_sync_action_respects_option():
    with patch("mitmproxy_mcp.view_sync.ctx") as mock_ctx:
        mock_ctx.options.mcp_view_sync_actions = "replay"
        assert should_sync_action("replay") is True
        assert should_sync_action("clear") is False


def test_configure_rejects_invalid_view_sync_actions():
    addon = MCPAddon()

    with patch("mitmproxy_mcp.addon.ctx") as mock_ctx:
        mock_ctx.options.mcp_view_sync_actions = "invalid"
        with pytest.raises(exceptions.OptionsError):
            addon.configure({"mcp_view_sync_actions"})


def test_configure_accepts_valid_view_sync_actions():
    addon = MCPAddon()

    with patch("mitmproxy_mcp.addon.ctx") as mock_ctx:
        mock_ctx.options.mcp_view_sync_actions = "clear,replay"
        addon.configure({"mcp_view_sync_actions"})
