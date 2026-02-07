"""Privacy and redaction engine for sensitive data in HTTP flows."""

import re
from typing import Dict, List, Optional, Pattern, Tuple, Any


# Default redaction patterns with their replacements
# Pattern tuples: (regex_pattern, replacement_string)
DEFAULT_PATTERNS: List[Tuple[str, str]] = [
    # Bearer tokens in Authorization headers
    (r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", "Bearer [REDACTED]"),
    # Basic auth (base64 encoded credentials)
    (r"Basic\s+[A-Za-z0-9+/]+=*", "Basic [REDACTED]"),
    # API keys in various formats (including JSON: "api_key": "value")
    (
        r'(api[_-]?key|apikey|x-api-key)\s*[=:"]+\s*["\']?([A-Za-z0-9\-._~+/]+)["\']?',
        r"\1=[REDACTED]",
    ),
    # Passwords in key=value, key:value, or JSON formats
    (
        r'(password|passwd|pwd|secret)\s*[=:"]+\s*["\']?([^\s&"\',}]+)["\']?',
        r"\1=[REDACTED]",
    ),
    # JWTs (three base64url segments separated by dots)
    (r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*", "[REDACTED_JWT]"),
    # Cookie session values (capture URL-encoded chars) - must come before generic session ID pattern
    (r"(connect\.sid|session|auth)\s*=\s*[A-Za-z0-9\-._~+/%:]+", r"\1=[REDACTED]"),
    # Session IDs in various formats
    (
        r'(session[_-]?id|sessionid|sid|jsessionid)\s*[=:"]+\s*["\']?([A-Za-z0-9\-._~+/]+)["\']?',
        r"\1=[REDACTED]",
    ),
    # Auth tokens in query strings and JSON
    (
        r'(access_token|auth_token)\s*[=:"]+\s*["\']?([A-Za-z0-9\-._~+/]+)["\']?',
        r"\1=[REDACTED]",
    ),
]

# Sensitive header names that should have their values redacted
SENSITIVE_HEADERS = {
    "authorization",
    "x-api-key",
    "api-key",
    "apikey",
    "x-auth-token",
    "x-access-token",
    "cookie",
    "set-cookie",
    "proxy-authorization",
}


class RedactionEngine:
    """Engine for redacting sensitive data from HTTP flows.

    Applies regex-based pattern matching to identify and redact sensitive
    information like tokens, passwords, API keys, and JWTs.
    """

    def __init__(self, custom_patterns: Optional[List[str]] = None) -> None:
        """Initialize with default + custom patterns.

        Args:
            custom_patterns: Optional list of additional regex patterns to redact.
                            Each match will be replaced with '[REDACTED]'.
        """
        self.patterns: List[Tuple[Pattern[str], str]] = []

        # Compile default patterns (case-insensitive)
        for pattern_str, replacement in DEFAULT_PATTERNS:
            self.patterns.append((re.compile(pattern_str, re.IGNORECASE), replacement))

        # Add custom patterns
        if custom_patterns:
            for pattern_str in custom_patterns:
                self.patterns.append(
                    (re.compile(pattern_str, re.IGNORECASE), "[REDACTED]")
                )

    def redact_string(self, text: Optional[str]) -> Optional[str]:
        """Redact sensitive data from a string.

        Args:
            text: Input string that may contain sensitive data

        Returns:
            String with sensitive data redacted, or None if input was None
        """
        if text is None:
            return None

        if not text:
            return text

        result = text
        for pattern, replacement in self.patterns:
            result = pattern.sub(replacement, result)
        return result

    def redact_dict(
        self, data: Dict[str, str], is_headers: bool = False
    ) -> Dict[str, str]:
        """Redact sensitive data from a dictionary (headers, query params).

        Args:
            data: Dictionary mapping keys to string values
            is_headers: If True, also redact values of known sensitive header names

        Returns:
            New dictionary with values redacted where needed
        """
        if not data:
            return data

        result = {}
        for k, v in data.items():
            if is_headers and k.lower() in SENSITIVE_HEADERS:
                result[k] = "[REDACTED]"
            else:
                result[k] = self.redact_string(v) or ""
        return result

    def redact_flow_detail(self, flow_detail: Dict[str, Any]) -> Dict[str, Any]:
        """Redact sensitive data from FlowDetail dict.

        Redacts request/response headers, bodies, and URLs.

        Args:
            flow_detail: Dictionary representation of a FlowDetail model

        Returns:
            Same dict with sensitive data redacted
        """
        # Redact request
        if "request" in flow_detail and flow_detail["request"]:
            request = flow_detail["request"]

            # Redact request headers
            if "headers" in request and request["headers"]:
                request["headers"] = self.redact_dict(
                    request["headers"], is_headers=True
                )

            # Redact request body
            if "body" in request and request["body"]:
                request["body"] = self.redact_string(request["body"])

            # Redact request URL (query params may contain secrets)
            if "url" in request and request["url"]:
                request["url"] = self.redact_string(request["url"])

        # Redact response
        if "response" in flow_detail and flow_detail["response"]:
            response = flow_detail["response"]

            # Redact response headers
            if "headers" in response and response["headers"]:
                response["headers"] = self.redact_dict(
                    response["headers"], is_headers=True
                )

            # Redact response body
            if "body" in response and response["body"]:
                response["body"] = self.redact_string(response["body"])

        return flow_detail

    def redact_flow_summary(self, flow_summary: Dict[str, Any]) -> Dict[str, Any]:
        """Redact sensitive data from FlowSummary dict.

        Args:
            flow_summary: Dictionary representation of a FlowSummary model

        Returns:
            Same dict with sensitive data redacted
        """
        # Redact URL (may contain tokens in query string)
        if "url" in flow_summary and flow_summary["url"]:
            flow_summary["url"] = self.redact_string(flow_summary["url"])

        return flow_summary

    def redact_request_model(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Redact sensitive data from RequestModel dict.

        Args:
            request: Dictionary representation of a RequestModel

        Returns:
            Same dict with sensitive data redacted
        """
        if not request:
            return request

        if "headers" in request and request["headers"]:
            request["headers"] = self.redact_dict(request["headers"], is_headers=True)

        if "body" in request and request["body"]:
            request["body"] = self.redact_string(request["body"])

        if "url" in request and request["url"]:
            request["url"] = self.redact_string(request["url"])

        return request

    def redact_response_model(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """Redact sensitive data from ResponseModel dict.

        Args:
            response: Dictionary representation of a ResponseModel

        Returns:
            Same dict with sensitive data redacted
        """
        if not response:
            return response

        if "headers" in response and response["headers"]:
            response["headers"] = self.redact_dict(response["headers"], is_headers=True)

        if "body" in response and response["body"]:
            response["body"] = self.redact_string(response["body"])

        return response

    def redact_har_entry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """Redact sensitive data from a HAR entry.

        Args:
            entry: HAR entry dictionary

        Returns:
            Same dict with sensitive data redacted
        """
        if not entry:
            return entry

        # Redact request
        if "request" in entry and entry["request"]:
            request = entry["request"]

            # Redact URL
            if "url" in request:
                request["url"] = self.redact_string(request["url"])

            # Redact headers (list of {name, value})
            if "headers" in request and request["headers"]:
                for header in request["headers"]:
                    if "value" in header and "name" in header:
                        if header["name"].lower() in SENSITIVE_HEADERS:
                            header["value"] = "[REDACTED]"
                        else:
                            header["value"] = self.redact_string(header["value"])

            if "queryString" in request and request["queryString"]:
                for param in request["queryString"]:
                    if "value" in param and "name" in param:
                        param_name = param["name"].lower()
                        if any(
                            s in param_name
                            for s in ["key", "token", "secret", "password", "auth"]
                        ):
                            param["value"] = "[REDACTED]"
                        else:
                            param["value"] = self.redact_string(param["value"])

            # Redact post data
            if "postData" in request and request["postData"]:
                if "text" in request["postData"]:
                    request["postData"]["text"] = self.redact_string(
                        request["postData"]["text"]
                    )

        # Redact response
        if "response" in entry and entry["response"]:
            response = entry["response"]

            # Redact headers
            if "headers" in response and response["headers"]:
                for header in response["headers"]:
                    if "value" in header:
                        header["value"] = self.redact_string(header["value"])

            # Redact content
            if "content" in response and response["content"]:
                if "text" in response["content"]:
                    response["content"]["text"] = self.redact_string(
                        response["content"]["text"]
                    )

        return entry


# Global instance (will be initialized by addon)
_redaction_engine: Optional[RedactionEngine] = None


def init_redaction_engine(custom_patterns: Optional[List[str]] = None) -> None:
    """Initialize the global redaction engine.

    Called by the addon during configure() to set up redaction.

    Args:
        custom_patterns: Optional list of custom regex patterns to redact
    """
    global _redaction_engine
    _redaction_engine = RedactionEngine(custom_patterns)


def get_redaction_engine() -> Optional[RedactionEngine]:
    """Get the global redaction engine instance.

    Returns:
        The RedactionEngine if initialized, None otherwise
    """
    return _redaction_engine


def reset_redaction_engine() -> None:
    """Reset the global redaction engine (for testing)."""
    global _redaction_engine
    _redaction_engine = None
