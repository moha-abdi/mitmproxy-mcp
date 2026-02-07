"""MCP tools for querying captured HTTP traffic flows."""

from typing import List, Any, Dict
import json
from datetime import datetime

import mcp.types as types

from storage import get_storage
from models import FlowDetail, RequestModel, ResponseModel
from privacy import get_redaction_engine


# Tool definitions for MCP server registration
FLOW_TOOLS: List[types.Tool] = [
    types.Tool(
        name="get_flows",
        description="List captured HTTP flows with pagination and filtering",
        inputSchema={
            "type": "object",
            "properties": {
                "offset": {
                    "type": "integer",
                    "description": "Number of flows to skip (default 0)",
                    "default": 0,
                    "minimum": 0,
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum flows to return (default 100, max 500)",
                    "default": 100,
                    "minimum": 1,
                    "maximum": 500,
                },
                "method": {
                    "type": "string",
                    "description": "Filter by HTTP method (GET, POST, etc.)",
                },
                "url_pattern": {
                    "type": "string",
                    "description": "Filter by URL regex pattern",
                },
                "status_code": {
                    "type": "integer",
                    "description": "Filter by response status code",
                },
            },
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="get_flow_by_id",
        description="Get complete details of a single flow by its ID",
        inputSchema={
            "type": "object",
            "properties": {
                "flow_id": {
                    "type": "string",
                    "description": "Unique flow identifier",
                },
            },
            "required": ["flow_id"],
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="search_flows",
        description="Search flows by regex pattern across URL, method, status, and headers",
        inputSchema={
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Regex pattern to search for",
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum results to return (default 100)",
                    "default": 100,
                    "minimum": 1,
                    "maximum": 500,
                },
            },
            "required": ["pattern"],
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="get_flow_request",
        description="Get only the request portion of a flow",
        inputSchema={
            "type": "object",
            "properties": {
                "flow_id": {
                    "type": "string",
                    "description": "Unique flow identifier",
                },
            },
            "required": ["flow_id"],
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="get_flow_response",
        description="Get only the response portion of a flow",
        inputSchema={
            "type": "object",
            "properties": {
                "flow_id": {
                    "type": "string",
                    "description": "Unique flow identifier",
                },
            },
            "required": ["flow_id"],
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="clear_flows",
        description="Clear all stored flows",
        inputSchema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="get_flow_count",
        description="Get total number of stored flows",
        inputSchema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="export_flows",
        description="Export flows to HAR (HTTP Archive) format",
        inputSchema={
            "type": "object",
            "properties": {
                "flow_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional list of flow IDs to export. Exports all if not provided.",
                },
            },
            "additionalProperties": False,
        },
    ),
]


def _flow_to_summary(flow: Any) -> Dict[str, Any]:
    """Convert mitmproxy flow to summary dict."""
    return {
        "id": flow.id,
        "method": flow.request.method,
        "url": flow.request.url,
        "status_code": flow.response.status_code if flow.response else None,
        "timestamp": datetime.fromtimestamp(flow.timestamp_start).isoformat(),
    }


def _flow_to_har_entry(flow: Any) -> Dict[str, Any]:
    """Convert a single mitmproxy flow to HAR entry format.

    HAR 1.2 spec: http://www.softwareishard.com/blog/har-12-spec/
    """
    request = flow.request
    response = flow.response

    # Request headers
    request_headers = [
        {"name": name, "value": value} for name, value in request.headers.items()
    ]

    # Request query string
    query_string = []
    if request.query:
        query_string = [
            {"name": name, "value": value} for name, value in request.query.items()
        ]

    # Request post data
    post_data = None
    if request.content:
        content_type = request.headers.get("content-type", "")
        try:
            text = request.content.decode("utf-8")
        except UnicodeDecodeError:
            text = "<binary content>"
        post_data = {
            "mimeType": content_type,
            "text": text,
        }

    # Build request entry
    har_request = {
        "method": request.method,
        "url": request.url,
        "httpVersion": f"HTTP/{request.http_version}",
        "cookies": [],  # TODO: parse cookies if needed
        "headers": request_headers,
        "queryString": query_string,
        "headersSize": -1,  # Unknown
        "bodySize": len(request.content) if request.content else 0,
    }
    if post_data:
        har_request["postData"] = post_data

    # Build response entry
    if response:
        response_headers = [
            {"name": name, "value": value} for name, value in response.headers.items()
        ]

        # Response content
        content_type = response.headers.get("content-type", "")
        response_content = {
            "size": len(response.content) if response.content else 0,
            "mimeType": content_type,
        }
        if response.content:
            try:
                response_content["text"] = response.content.decode("utf-8")
            except UnicodeDecodeError:
                import base64

                response_content["text"] = base64.b64encode(response.content).decode(
                    "ascii"
                )
                response_content["encoding"] = "base64"

        har_response = {
            "status": response.status_code,
            "statusText": response.reason or "",
            "httpVersion": f"HTTP/{response.http_version}",
            "cookies": [],
            "headers": response_headers,
            "content": response_content,
            "redirectURL": response.headers.get("location", ""),
            "headersSize": -1,
            "bodySize": len(response.content) if response.content else 0,
        }
    else:
        har_response = {
            "status": 0,
            "statusText": "",
            "httpVersion": "HTTP/1.1",
            "cookies": [],
            "headers": [],
            "content": {"size": 0, "mimeType": ""},
            "redirectURL": "",
            "headersSize": -1,
            "bodySize": 0,
        }

    # Calculate timings
    started = datetime.fromtimestamp(request.timestamp_start)
    wait_time = 0
    receive_time = 0
    if response:
        if response.timestamp_start:
            wait_time = int((response.timestamp_start - request.timestamp_end) * 1000)
        if response.timestamp_end:
            receive_time = int(
                (response.timestamp_end - response.timestamp_start) * 1000
            )

    timings = {
        "send": 0,  # Time to send request (not tracked)
        "wait": max(0, wait_time),  # Time waiting for response
        "receive": max(0, receive_time),  # Time receiving response
    }

    total_time = timings["send"] + timings["wait"] + timings["receive"]

    return {
        "startedDateTime": started.isoformat() + "Z",
        "time": total_time,
        "request": har_request,
        "response": har_response,
        "cache": {},
        "timings": timings,
    }


async def handle_flow_tool(
    name: str, arguments: Dict[str, Any]
) -> List[types.TextContent]:
    """Handle flow-related MCP tool calls.

    Args:
        name: Tool name
        arguments: Tool arguments

    Returns:
        List of TextContent with JSON result
    """
    storage = get_storage()

    if name == "get_flows":
        offset = arguments.get("offset", 0)
        limit = min(arguments.get("limit", 100), 500)
        method = arguments.get("method")
        url_pattern = arguments.get("url_pattern")
        status_code = arguments.get("status_code")

        flows = storage.get_all(
            offset=offset,
            limit=limit,
            method=method,
            url_pattern=url_pattern,
            status_code=status_code,
        )

        summaries = [_flow_to_summary(f) for f in flows]

        engine = get_redaction_engine()
        if engine:
            summaries = [engine.redact_flow_summary(s) for s in summaries]

        result = {
            "total": storage.count(),
            "offset": offset,
            "limit": limit,
            "count": len(summaries),
            "flows": summaries,
        }
        return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

    elif name == "get_flow_by_id":
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

        detail = FlowDetail.from_mitmproxy(flow)
        detail_dict = json.loads(detail.model_dump_json())

        engine = get_redaction_engine()
        if engine:
            detail_dict = engine.redact_flow_detail(detail_dict)

        return [types.TextContent(type="text", text=json.dumps(detail_dict, indent=2))]

    elif name == "search_flows":
        pattern = arguments.get("pattern")
        if not pattern:
            return [
                types.TextContent(type="text", text='{"error": "pattern is required"}')
            ]

        limit = min(arguments.get("limit", 100), 500)
        flows = storage.search(pattern)[:limit]

        summaries = [_flow_to_summary(f) for f in flows]

        engine = get_redaction_engine()
        if engine:
            summaries = [engine.redact_flow_summary(s) for s in summaries]

        result = {
            "pattern": pattern,
            "count": len(summaries),
            "flows": summaries,
        }
        return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

    elif name == "get_flow_request":
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

        request = RequestModel.from_mitmproxy(flow.request)
        request_dict = json.loads(request.model_dump_json())

        engine = get_redaction_engine()
        if engine:
            request_dict = engine.redact_request_model(request_dict)

        return [types.TextContent(type="text", text=json.dumps(request_dict, indent=2))]

    elif name == "get_flow_response":
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

        if not flow.response:
            return [
                types.TextContent(
                    type="text",
                    text=f'{{"error": "No response yet for flow: {flow_id}"}}',
                )
            ]

        response = ResponseModel.from_mitmproxy(flow.response)
        response_dict = json.loads(response.model_dump_json())

        engine = get_redaction_engine()
        if engine:
            response_dict = engine.redact_response_model(response_dict)

        return [
            types.TextContent(type="text", text=json.dumps(response_dict, indent=2))
        ]

    elif name == "clear_flows":
        count = storage.clear()
        result = {"cleared": count, "message": f"Cleared {count} flows"}
        return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

    elif name == "get_flow_count":
        count = storage.count()
        max_flows = storage.max_flows
        result = {"count": count, "max_flows": max_flows}
        return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

    elif name == "export_flows":
        flow_ids = arguments.get("flow_ids")

        if flow_ids:
            # Export specific flows
            flows = []
            for fid in flow_ids:
                flow = storage.get(fid)
                if flow:
                    flows.append(flow)
        else:
            # Export all flows
            flows = storage.get_all(offset=0, limit=storage.max_flows)

        entries = [_flow_to_har_entry(f) for f in flows]

        engine = get_redaction_engine()
        if engine:
            entries = [engine.redact_har_entry(e) for e in entries]

        har = {
            "log": {
                "version": "1.2",
                "creator": {
                    "name": "mitmproxy-mcp",
                    "version": "0.1.0",
                },
                "entries": entries,
            }
        }

        return [types.TextContent(type="text", text=json.dumps(har, indent=2))]

    else:
        return [
            types.TextContent(type="text", text=f'{{"error": "Unknown tool: {name}"}}')
        ]
