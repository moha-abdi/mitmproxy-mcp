"""Pydantic models for mitmproxy flow serialization."""

from typing import Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime
import base64

# Configuration
MAX_BODY_SIZE = 10 * 1024  # 10KB default


def truncate_body(
    content: Optional[bytes], max_size: int = MAX_BODY_SIZE
) -> Optional[str]:
    """
    Convert bytes content to string with truncation.

    Attempts UTF-8 decode first. Falls back to base64 for binary content.
    Appends "[TRUNCATED]" marker if content exceeds max_size.

    Args:
        content: Raw bytes content
        max_size: Maximum size before truncation (default 10KB)

    Returns:
        Decoded/encoded string or None if content is None
    """
    if content is None:
        return None

    # Try UTF-8 decode first
    try:
        decoded = content.decode("utf-8")
        if len(content) > max_size:
            # Truncate at max_size and append marker
            truncated = decoded[:max_size]
            return f"{truncated}\n... [TRUNCATED - {len(content) - max_size} bytes omitted]"
        return decoded
    except UnicodeDecodeError:
        # Fall back to base64 for binary content
        encoded = base64.b64encode(content).decode("ascii")
        if len(content) > max_size:
            # Truncate base64 representation
            truncated_b64 = encoded[:max_size]
            return f"{truncated_b64}\n... [TRUNCATED BINARY - {len(content) - max_size} bytes omitted]"
        return f"<binary: {encoded}>"


def headers_to_dict(headers: Any) -> Dict[str, str]:
    """
    Convert mitmproxy Headers object to Dict[str, str].

    mitmproxy.http.Headers has an items() method that returns (name, value) tuples.
    For multi-value headers, joins with comma.

    Args:
        headers: mitmproxy Headers object

    Returns:
        Dictionary mapping header names to values
    """
    result: dict[str, str] = {}
    if headers is None:
        return result

    # Use .items() method for mitmproxy Headers
    if hasattr(headers, "items"):
        items = headers.items()
    else:
        # Fallback for other iterables
        items = headers

    for name, value in items:
        # Convert bytes to str if needed
        if isinstance(name, bytes):
            name = name.decode("utf-8", errors="replace")
        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="replace")

        # Handle multi-value headers by joining with comma
        if name in result:
            result[name] = f"{result[name]}, {value}"
        else:
            result[name] = value

    return result


class RequestModel(BaseModel):
    """HTTP request representation."""

    method: str = Field(..., description="HTTP method (GET, POST, etc.)")
    url: str = Field(..., description="Full request URL")
    headers: Dict[str, str] = Field(default_factory=dict, description="Request headers")
    body: Optional[str] = Field(None, description="Request body (truncated if > 10KB)")
    timestamp: datetime = Field(..., description="Request timestamp")

    class Config:
        arbitrary_types_allowed = True

    @classmethod
    def from_mitmproxy(
        cls, request: Any, max_body_size: int = MAX_BODY_SIZE
    ) -> "RequestModel":
        """
        Convert mitmproxy Request to RequestModel.

        Args:
            request: mitmproxy.http.Request object
            max_body_size: Maximum body size before truncation

        Returns:
            RequestModel instance
        """
        return cls(
            method=request.method.decode("utf-8")
            if isinstance(request.method, bytes)
            else request.method,
            url=request.url,
            headers=headers_to_dict(request.headers),
            body=truncate_body(request.content, max_body_size),
            timestamp=datetime.fromtimestamp(request.timestamp_start),
        )


class ResponseModel(BaseModel):
    """HTTP response representation."""

    status_code: int = Field(..., description="HTTP status code")
    reason: Optional[str] = Field(None, description="HTTP reason phrase")
    headers: Dict[str, str] = Field(
        default_factory=dict, description="Response headers"
    )
    body: Optional[str] = Field(None, description="Response body (truncated if > 10KB)")
    timestamp: datetime = Field(..., description="Response timestamp")

    class Config:
        arbitrary_types_allowed = True

    @classmethod
    def from_mitmproxy(
        cls, response: Any, max_body_size: int = MAX_BODY_SIZE
    ) -> "ResponseModel":
        """
        Convert mitmproxy Response to ResponseModel.

        Args:
            response: mitmproxy.http.Response object
            max_body_size: Maximum body size before truncation

        Returns:
            ResponseModel instance
        """
        reason = response.reason
        if isinstance(reason, bytes):
            reason = reason.decode("utf-8", errors="replace")

        return cls(
            status_code=response.status_code,
            reason=reason,
            headers=headers_to_dict(response.headers),
            body=truncate_body(response.content, max_body_size),
            timestamp=datetime.fromtimestamp(response.timestamp_start),
        )


class FlowSummary(BaseModel):
    """Minimal flow info for listings."""

    id: str = Field(..., description="Unique flow ID")
    method: str = Field(..., description="HTTP method")
    url: str = Field(..., description="Request URL")
    status_code: Optional[int] = Field(
        None, description="Response status code (None if no response)"
    )
    timestamp: datetime = Field(..., description="Flow start timestamp")


class FlowDetail(BaseModel):
    """Complete flow with request/response."""

    id: str = Field(..., description="Unique flow ID")
    request: RequestModel = Field(..., description="HTTP request")
    response: Optional[ResponseModel] = Field(
        None, description="HTTP response (None if not yet received)"
    )
    timestamp_start: datetime = Field(..., description="Flow start timestamp")
    timestamp_end: Optional[datetime] = Field(None, description="Flow end timestamp")
    error: Optional[str] = Field(None, description="Error message if flow failed")

    class Config:
        arbitrary_types_allowed = True

    @classmethod
    def from_mitmproxy(
        cls, flow: Any, max_body_size: int = MAX_BODY_SIZE
    ) -> "FlowDetail":
        """
        Convert mitmproxy HTTPFlow to FlowDetail.

        Args:
            flow: mitmproxy.http.HTTPFlow object
            max_body_size: Maximum body size before truncation

        Returns:
            FlowDetail instance
        """
        # Convert request
        request = RequestModel.from_mitmproxy(flow.request, max_body_size)

        # Convert response if present
        response = None
        if flow.response is not None:
            response = ResponseModel.from_mitmproxy(flow.response, max_body_size)

        # Convert error if present
        error_msg = None
        if flow.error is not None:
            error_msg = (
                flow.error.msg if hasattr(flow.error, "msg") else str(flow.error)
            )

        # Use timestamp_created as end time (mitmproxy doesn't have timestamp_end)
        timestamp_end = None
        if hasattr(flow, "timestamp_created") and flow.timestamp_created:
            timestamp_end = datetime.fromtimestamp(flow.timestamp_created)

        return cls(
            id=flow.id,
            request=request,
            response=response,
            timestamp_start=datetime.fromtimestamp(flow.timestamp_start),
            timestamp_end=timestamp_end,
            error=error_msg,
        )
