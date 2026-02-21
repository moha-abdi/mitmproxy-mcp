"""MCP tools for replaying and modifying HTTP requests."""

import asyncio
from typing import List, Optional, Dict, Any
import json
import uuid
import time

import httpx
import mcp.types as types
from mitmproxy import connection, ctx, http

from ..storage import get_storage
from ..models import FlowDetail
from ..privacy import get_redaction_engine
from ..view_sync import should_sync_action


REPLAY_TOOLS: List[types.Tool] = [
    types.Tool(
        name="replay_request",
        description="Replay a captured request as-is. When mcp_view_sync_actions includes replay, the original flow is replayed in-place; otherwise a detached replay flow is created.",
        inputSchema={
            "type": "object",
            "properties": {
                "flow_id": {
                    "type": "string",
                    "description": "ID of the flow to replay",
                },
            },
            "required": ["flow_id"],
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="send_request",
        description="Send an arbitrary HTTP request. Creates a new flow with the request/response, and adds it to mitmproxy's view based on mcp_view_sync_actions (action: replay).",
        inputSchema={
            "type": "object",
            "properties": {
                "method": {
                    "type": "string",
                    "description": "HTTP method (GET, POST, PUT, DELETE, etc.)",
                    "default": "GET",
                },
                "url": {
                    "type": "string",
                    "description": "Full URL to send the request to",
                },
                "headers": {
                    "type": "object",
                    "description": "Optional headers as key-value pairs",
                    "additionalProperties": {"type": "string"},
                },
                "body": {
                    "type": "string",
                    "description": "Optional request body",
                },
            },
            "required": ["url"],
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="modify_and_send",
        description="Modify a captured request and send it. Allows changing method, URL, headers, or body, and adds the resulting flow to mitmproxy's view based on mcp_view_sync_actions (action: replay).",
        inputSchema={
            "type": "object",
            "properties": {
                "flow_id": {
                    "type": "string",
                    "description": "ID of the flow to modify and send",
                },
                "method": {
                    "type": "string",
                    "description": "New HTTP method (optional, keeps original if not specified)",
                },
                "url": {
                    "type": "string",
                    "description": "New URL (optional, keeps original if not specified)",
                },
                "headers": {
                    "type": "object",
                    "description": "Headers to add or replace (optional)",
                    "additionalProperties": {"type": "string"},
                },
                "remove_headers": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Header names to remove (optional)",
                },
                "body": {
                    "type": "string",
                    "description": "New request body (optional, keeps original if not specified)",
                },
            },
            "required": ["flow_id"],
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="duplicate_flow",
        description="Clone a flow for modification. Creates a copy with a new ID without sending, and adds it to mitmproxy's view based on mcp_view_sync_actions (action: replay).",
        inputSchema={
            "type": "object",
            "properties": {
                "flow_id": {
                    "type": "string",
                    "description": "ID of the flow to duplicate",
                },
            },
            "required": ["flow_id"],
            "additionalProperties": False,
        },
    ),
]


def _create_flow_from_params(
    method: str,
    url: str,
    headers: Optional[Dict[str, str]] = None,
    body: Optional[str] = None,
) -> http.HTTPFlow:
    from urllib.parse import urlparse

    parsed = urlparse(url)
    host = parsed.netloc

    headers_list = []
    if headers:
        for key, value in headers.items():
            headers_list.append((key.encode(), value.encode()))

    host_header_present = any(k.lower() == b"host" for k, _ in headers_list)
    if not host_header_present:
        headers_list.insert(0, (b"Host", host.encode()))

    request = http.Request.make(
        method=method,
        url=url,
        content=body.encode() if body else b"",
        headers=headers_list,
    )

    return _create_synthetic_flow(request)


def _create_synthetic_flow(request: http.Request) -> http.HTTPFlow:
    timestamp_start = request.timestamp_start or time.time()
    client_conn = connection.Client(
        peername=("127.0.0.1", 0),
        sockname=("0.0.0.0", 0),
        timestamp_start=timestamp_start,
    )
    server_conn = connection.Server(address=(request.host, request.port))

    flow = http.HTTPFlow(client_conn=client_conn, server_conn=server_conn)
    flow.request = request
    flow.id = str(uuid.uuid4())
    return flow


def _duplicate_flow(original: http.HTTPFlow) -> http.HTTPFlow:
    headers_bytes = [
        (k.encode(), v.encode()) for k, v in original.request.headers.items()
    ]
    request = http.Request.make(
        method=original.request.method,
        url=original.request.url,
        content=original.request.content or b"",
        headers=headers_bytes,
    )
    new_flow = _create_synthetic_flow(request)

    if original.response:
        resp_headers_bytes = [
            (k.encode(), v.encode()) for k, v in original.response.headers.items()
        ]
        new_flow.response = http.Response.make(
            status_code=original.response.status_code,
            content=original.response.content or b"",
            headers=resp_headers_bytes,
        )

    new_flow.id = str(uuid.uuid4())

    return new_flow


def _should_add_replay_flow_to_view() -> bool:
    return should_sync_action("replay", getattr(ctx, "options", None))


def _add_flow_to_view(flow: http.HTTPFlow) -> None:
    if not _should_add_replay_flow_to_view():
        return

    master = getattr(ctx, "master", None)
    if master is None:
        return

    addons = getattr(master, "addons", None)
    if addons is None:
        return

    try:
        view_addon = addons.get("view")
        if view_addon is not None and hasattr(view_addon, "add"):
            view_addon.add([flow])
    except Exception:
        pass


def _record_flow(storage, flow: http.HTTPFlow) -> None:
    storage.add(flow)
    _add_flow_to_view(flow)


def _remove_httpx_managed_headers(headers: Dict[str, str]) -> Dict[str, str]:
    managed_headers = {"content-length", "transfer-encoding", "host"}
    return {k: v for k, v in headers.items() if k.lower() not in managed_headers}


async def _replay_request_in_place(flow: http.HTTPFlow) -> http.HTTPFlow:
    from mitmproxy.flow import Error as FlowError

    master = getattr(ctx, "master", None)
    if master is None:
        flow.error = FlowError("mitmproxy master is unavailable for replay")
        return flow

    commands = getattr(master, "commands", None)
    if commands is None:
        flow.error = FlowError("mitmproxy commands are unavailable for replay")
        return flow

    try:
        commands.call("replay.client", [flow])
    except Exception as e:
        flow.error = FlowError(f"Failed to queue replay: {str(e)}")
        return flow

    if getattr(flow, "is_replay", None) != "request":
        flow.error = FlowError("Flow could not be queued for replay")
        return flow

    start = time.time()
    timeout_seconds = 30.0
    while flow.response is None and flow.error is None:
        if (time.time() - start) >= timeout_seconds:
            flow.error = FlowError("Replay timed out waiting for response")
            break
        await asyncio.sleep(0.01)

    return flow


async def _send_http_request(flow: http.HTTPFlow) -> http.HTTPFlow:
    request = flow.request
    headers = _remove_httpx_managed_headers(dict(request.headers.items()))

    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=False) as client:
            start_time = time.time()
            response = await client.request(
                method=request.method,
                url=request.url,
                headers=headers,
                content=request.content if request.content else None,
                timeout=30.0,
            )
            end_time = time.time()

            resp_headers_bytes = [
                (k.encode(), v.encode()) for k, v in response.headers.items()
            ]
            flow.response = http.Response.make(
                status_code=response.status_code,
                content=response.content,
                headers=resp_headers_bytes,
            )

            flow.request.timestamp_start = start_time
            flow.request.timestamp_end = start_time + 0.001
            flow.response.timestamp_start = start_time + 0.001
            flow.response.timestamp_end = end_time

    except httpx.RequestError as e:
        from mitmproxy.flow import Error as FlowError

        flow.error = FlowError(str(e))

    return flow


async def handle_replay_tool(
    name: str, arguments: Dict[str, Any]
) -> List[types.TextContent]:
    storage = get_storage()

    if name == "replay_request":
        flow_id = arguments.get("flow_id")
        if not flow_id:
            return [
                types.TextContent(type="text", text='{"error": "flow_id is required"}')
            ]

        original = storage.get(flow_id)
        if not original:
            return [
                types.TextContent(
                    type="text", text=f'{{"error": "Flow not found: {flow_id}"}}'
                )
            ]

        if _should_add_replay_flow_to_view():
            replayed_flow = await _replay_request_in_place(original)
            storage.add(replayed_flow)
        else:
            replayed_flow = _duplicate_flow(original)
            replayed_flow = await _send_http_request(replayed_flow)
            _record_flow(storage, replayed_flow)

        result = {
            "original_flow_id": flow_id,
            "new_flow_id": replayed_flow.id,
            "replayed_in_place": replayed_flow.id == flow_id,
            "status": "success" if replayed_flow.response else "error",
            "status_code": replayed_flow.response.status_code
            if replayed_flow.response
            else None,
            "error": str(replayed_flow.error)
            if hasattr(replayed_flow, "error") and replayed_flow.error
            else None,
        }
        return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

    elif name == "send_request":
        url = arguments.get("url")
        if not url:
            return [types.TextContent(type="text", text='{"error": "url is required"}')]

        method = arguments.get("method", "GET").upper()
        headers = arguments.get("headers", {})
        body = arguments.get("body")

        new_flow = _create_flow_from_params(method, url, headers, body)
        new_flow = await _send_http_request(new_flow)
        _record_flow(storage, new_flow)

        result = {
            "flow_id": new_flow.id,
            "method": method,
            "url": url,
            "status": "success" if new_flow.response else "error",
            "status_code": new_flow.response.status_code if new_flow.response else None,
            "error": str(new_flow.error)
            if hasattr(new_flow, "error") and new_flow.error
            else None,
        }
        return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

    elif name == "modify_and_send":
        flow_id = arguments.get("flow_id")
        if not flow_id:
            return [
                types.TextContent(type="text", text='{"error": "flow_id is required"}')
            ]

        original = storage.get(flow_id)
        if not original:
            return [
                types.TextContent(
                    type="text", text=f'{{"error": "Flow not found: {flow_id}"}}'
                )
            ]

        new_flow = _duplicate_flow(original)

        if "method" in arguments and arguments["method"]:
            new_flow.request.method = arguments["method"].upper()

        if "url" in arguments and arguments["url"]:
            new_flow.request.url = arguments["url"]
            new_flow.server_conn.address = (
                new_flow.request.host,
                new_flow.request.port,
            )

        if "remove_headers" in arguments:
            for header_name in arguments["remove_headers"]:
                for key in list(new_flow.request.headers.keys()):
                    if key.lower() == header_name.lower():
                        del new_flow.request.headers[key]

        if "headers" in arguments and arguments["headers"]:
            for key, value in arguments["headers"].items():
                new_flow.request.headers[key] = value

        if "body" in arguments and arguments["body"] is not None:
            new_flow.request.content = arguments["body"].encode()

        new_flow.response = None
        new_flow = await _send_http_request(new_flow)
        _record_flow(storage, new_flow)

        result = {
            "original_flow_id": flow_id,
            "new_flow_id": new_flow.id,
            "modifications": {
                "method": arguments.get("method"),
                "url": arguments.get("url"),
                "headers_added": list(arguments.get("headers", {}).keys()),
                "headers_removed": arguments.get("remove_headers", []),
                "body_modified": "body" in arguments,
            },
            "status": "success" if new_flow.response else "error",
            "status_code": new_flow.response.status_code if new_flow.response else None,
            "error": str(new_flow.error)
            if hasattr(new_flow, "error") and new_flow.error
            else None,
        }
        return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

    elif name == "duplicate_flow":
        flow_id = arguments.get("flow_id")
        if not flow_id:
            return [
                types.TextContent(type="text", text='{"error": "flow_id is required"}')
            ]

        original = storage.get(flow_id)
        if not original:
            return [
                types.TextContent(
                    type="text", text=f'{{"error": "Flow not found: {flow_id}"}}'
                )
            ]

        new_flow = _duplicate_flow(original)
        _record_flow(storage, new_flow)

        detail = FlowDetail.from_mitmproxy(new_flow)
        flow_dict = json.loads(detail.model_dump_json())

        engine = get_redaction_engine()
        if engine:
            flow_dict = engine.redact_flow_detail(flow_dict)

        result = {
            "original_flow_id": flow_id,
            "new_flow_id": new_flow.id,
            "message": "Flow duplicated successfully. Use modify_and_send to modify and send.",
            "flow": flow_dict,
        }
        return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

    else:
        return [
            types.TextContent(type="text", text=f'{{"error": "Unknown tool: {name}"}}')
        ]
