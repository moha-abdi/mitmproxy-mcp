"""MCP tools for controlling mitmproxy request/response interception."""

from typing import List, Dict, Any, Optional
import json
from datetime import datetime

import mcp.types as types
from mitmproxy import flowfilter

from storage import get_storage


_intercept_filter: Optional[str] = None
_parsed_filter: Optional[flowfilter.TFilter] = None


def get_intercept_filter() -> Optional[str]:
    """Get the current intercept filter string."""
    return _intercept_filter


def get_parsed_filter() -> Optional[flowfilter.TFilter]:
    """Get the parsed intercept filter for matching."""
    return _parsed_filter


def set_intercept_filter_internal(filter_str: str) -> Dict[str, Any]:
    """Set the intercept filter pattern.

    Args:
        filter_str: mitmproxy filter syntax (e.g., '~u httpbin', '~m POST').
                   Empty string disables interception.

    Returns:
        Dict with status, filter, and message.
    """
    global _intercept_filter, _parsed_filter

    if not filter_str:
        _intercept_filter = None
        _parsed_filter = None
        return {
            "status": "success",
            "filter": "",
            "message": "Interception disabled",
        }

    try:
        parsed = flowfilter.parse(filter_str)
    except ValueError as e:
        return {
            "status": "error",
            "filter": filter_str,
            "message": f"Invalid filter syntax: {filter_str}",
        }

    if parsed is None:
        return {
            "status": "error",
            "filter": filter_str,
            "message": f"Invalid filter syntax: {filter_str}",
        }

    _intercept_filter = filter_str
    _parsed_filter = parsed
    return {
        "status": "success",
        "filter": filter_str,
        "message": f"Intercept filter set to: '{filter_str}'",
    }


INTERCEPT_TOOLS: List[types.Tool] = [
    types.Tool(
        name="set_intercept_filter",
        description="Set mitmproxy intercept filter to pause matching requests. Uses mitmproxy filter syntax (e.g., '~u httpbin' for URL, '~m POST' for method). Empty string disables interception.",
        inputSchema={
            "type": "object",
            "properties": {
                "filter": {
                    "type": "string",
                    "description": "Intercept filter pattern using mitmproxy filter syntax. Examples: '~u httpbin' (URL contains httpbin), '~m POST' (POST requests), '~u api & ~m GET' (GET requests to URLs with api). Empty string disables interception.",
                },
            },
            "required": ["filter"],
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="get_intercepted_flows",
        description="List all currently intercepted flows that are awaiting resume or drop decision",
        inputSchema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="resume_flow",
        description="Resume a single intercepted flow to continue processing",
        inputSchema={
            "type": "object",
            "properties": {
                "flow_id": {
                    "type": "string",
                    "description": "ID of the intercepted flow to resume",
                },
            },
            "required": ["flow_id"],
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="resume_all",
        description="Resume all currently intercepted flows",
        inputSchema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="drop_flow",
        description="Drop/kill an intercepted flow without forwarding to server. The flow will be terminated with an error.",
        inputSchema={
            "type": "object",
            "properties": {
                "flow_id": {
                    "type": "string",
                    "description": "ID of the intercepted flow to drop",
                },
            },
            "required": ["flow_id"],
            "additionalProperties": False,
        },
    ),
]


def _flow_to_intercept_summary(flow: Any) -> Dict[str, Any]:
    """Convert an intercepted flow to a summary dict."""
    return {
        "id": flow.id,
        "method": flow.request.method,
        "url": flow.request.url,
        "status_code": flow.response.status_code if flow.response else None,
        "timestamp": datetime.fromtimestamp(flow.timestamp_start).isoformat(),
        "intercepted": flow.intercepted,
    }


async def handle_intercept_tool(
    name: str, arguments: Dict[str, Any]
) -> List[types.TextContent]:
    """Handle interception control MCP tool calls.

    Args:
        name: Tool name
        arguments: Tool arguments

    Returns:
        List of TextContent with JSON result
    """
    storage = get_storage()

    if name == "set_intercept_filter":
        filter_str = arguments.get("filter", "")
        result = set_intercept_filter_internal(filter_str)
        return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

    elif name == "get_intercepted_flows":
        intercepted = []
        for flow_id in storage._flow_order:
            flow = storage._flows.get(flow_id)
            if flow and flow.intercepted:
                intercepted.append(_flow_to_intercept_summary(flow))

        result = {
            "count": len(intercepted),
            "current_filter": _intercept_filter,
            "flows": intercepted,
        }
        return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

    elif name == "resume_flow":
        flow_id = arguments.get("flow_id")
        if not flow_id:
            return [
                types.TextContent(type="text", text='{"error": "flow_id is required"}')
            ]

        flow = storage.get(flow_id)
        if not flow:
            return [
                types.TextContent(
                    type="text", text=f'{{"error": "Flow not found: {flow_id}"}}'
                )
            ]

        if not flow.intercepted:
            return [
                types.TextContent(
                    type="text",
                    text=f'{{"error": "Flow is not intercepted: {flow_id}"}}',
                )
            ]

        flow.resume()

        result = {
            "status": "success",
            "flow_id": flow_id,
            "message": "Flow resumed",
        }
        return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

    elif name == "resume_all":
        resumed_count = 0
        resumed_ids = []

        for flow_id in storage._flow_order:
            flow = storage._flows.get(flow_id)
            if flow and flow.intercepted:
                flow.resume()
                resumed_count += 1
                resumed_ids.append(flow_id)

        result = {
            "status": "success",
            "resumed_count": resumed_count,
            "resumed_flow_ids": resumed_ids,
            "message": f"Resumed {resumed_count} flows",
        }
        return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

    elif name == "drop_flow":
        flow_id = arguments.get("flow_id")
        if not flow_id:
            return [
                types.TextContent(type="text", text='{"error": "flow_id is required"}')
            ]

        flow = storage.get(flow_id)
        if not flow:
            return [
                types.TextContent(
                    type="text", text=f'{{"error": "Flow not found: {flow_id}"}}'
                )
            ]

        if not flow.intercepted:
            return [
                types.TextContent(
                    type="text",
                    text=f'{{"error": "Flow is not intercepted: {flow_id}"}}',
                )
            ]

        flow.kill()

        result = {
            "status": "success",
            "flow_id": flow_id,
            "message": "Flow dropped/killed",
        }
        return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

    else:
        return [
            types.TextContent(type="text", text=f'{{"error": "Unknown tool: {name}"}}')
        ]
