from typing import List, Dict, Any
import json

import mcp.types as types
from mitmproxy import ctx, version

from ..storage import get_storage


BLOCKED_OPTIONS = {
    "listen_host",
    "listen_port",
    "mode",
    "server",
    "ssl_insecure",
}

CURATED_OPTIONS = [
    "listen_host",
    "listen_port",
    "mode",
    "intercept",
    "flow_detail",
    "ssl_insecure",
    "anticache",
    "anticomp",
    "showhost",
]


CONFIG_TOOLS: List[types.Tool] = [
    types.Tool(
        name="get_options",
        description="Get current mitmproxy option values. Returns curated set of commonly useful options by default, or specific options if keys are provided.",
        inputSchema={
            "type": "object",
            "properties": {
                "keys": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional list of specific option keys to retrieve. If not provided, returns curated set of common options.",
                },
            },
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="set_option",
        description="Set a mitmproxy option value. Blocks dangerous options like listen_host, listen_port, mode, server, and ssl_insecure.",
        inputSchema={
            "type": "object",
            "properties": {
                "key": {
                    "type": "string",
                    "description": "Option key to set",
                },
                "value": {
                    "description": "Option value (type depends on the option)",
                },
            },
            "required": ["key", "value"],
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="get_status",
        description="Get proxy status information including version, listen address, mode, flow count, and interception settings.",
        inputSchema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    ),
]


async def handle_config_tool(
    name: str, arguments: Dict[str, Any]
) -> List[types.TextContent]:
    if name == "get_options":
        keys = arguments.get("keys")

        if keys is not None:
            result = {}
            for key in keys:
                try:
                    value = getattr(ctx.options, key, None)
                    result[key] = value
                except (AttributeError, TypeError):
                    result[key] = None
        else:
            result = {}
            for key in CURATED_OPTIONS:
                try:
                    value = getattr(ctx.options, key, None)
                    result[key] = value
                except (AttributeError, TypeError):
                    result[key] = None

        return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

    elif name == "set_option":
        key = arguments.get("key")
        value = arguments.get("value")

        if not key:
            return [types.TextContent(type="text", text='{"error": "key is required"}')]

        if key in BLOCKED_OPTIONS:
            return [
                types.TextContent(
                    type="text",
                    text=json.dumps(
                        {
                            "error": f"Option '{key}' is blocked and cannot be modified",
                            "blocked_options": list(BLOCKED_OPTIONS),
                        },
                        indent=2,
                    ),
                )
            ]

        if not hasattr(ctx.options, key):
            return [
                types.TextContent(
                    type="text",
                    text=json.dumps(
                        {
                            "error": f"Option '{key}' does not exist",
                        },
                        indent=2,
                    ),
                )
            ]

        try:
            ctx.options.update(**{key: value})
            return [
                types.TextContent(
                    type="text",
                    text=json.dumps(
                        {
                            "status": "success",
                            "key": key,
                            "value": value,
                            "message": f"Option '{key}' set successfully",
                        },
                        indent=2,
                    ),
                )
            ]
        except Exception as e:
            return [
                types.TextContent(
                    type="text",
                    text=json.dumps(
                        {
                            "error": f"Failed to set option: {str(e)}",
                        },
                        indent=2,
                    ),
                )
            ]

    elif name == "get_status":
        storage = get_storage()

        result = {
            "version": version.VERSION,
            "listen_address": f"{ctx.options.listen_host}:{ctx.options.listen_port}",
            "mode": ctx.options.mode,
            "flow_count": len(storage._flows),
            "intercept_filter": getattr(ctx.options, "intercept", None),
            "anticache": ctx.options.anticache,
            "anticomp": ctx.options.anticomp,
        }

        return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

    else:
        return [
            types.TextContent(type="text", text=f'{{"error": "Unknown tool: {name}"}}')
        ]
