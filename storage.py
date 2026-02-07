"""In-memory flow storage for MCP tools."""

from typing import Dict, List, Optional
from mitmproxy import http
from threading import Lock
import re


class FlowStorage:
    """Thread-safe in-memory storage for HTTP flows.

    Stores flows with FIFO eviction when max_flows limit is reached.
    Uses threading.Lock for concurrent access safety.
    """

    def __init__(self, max_flows: int = 1000):
        """Initialize FlowStorage.

        Args:
            max_flows: Maximum number of flows to store (default 1000).
                       Oldest flows are evicted when limit is reached.
        """
        self._flows: Dict[str, http.HTTPFlow] = {}
        self._flow_order: List[str] = []  # Maintains insertion order for FIFO eviction
        self._max_flows = max_flows
        self._lock = Lock()

    def add(self, flow: http.HTTPFlow) -> None:
        """Add flow to storage, evicting oldest if at limit.

        If the flow already exists (by ID), it updates the existing flow.

        Args:
            flow: mitmproxy HTTPFlow to store
        """
        with self._lock:
            flow_id = flow.id

            # Update existing flow (e.g., when response arrives)
            if flow_id in self._flows:
                self._flows[flow_id] = flow
                return

            # Evict oldest flows if at limit
            while len(self._flow_order) >= self._max_flows:
                oldest_id = self._flow_order.pop(0)
                del self._flows[oldest_id]

            # Add new flow
            self._flows[flow_id] = flow
            self._flow_order.append(flow_id)

    def get(self, flow_id: str) -> Optional[http.HTTPFlow]:
        """Get flow by ID.

        Args:
            flow_id: Unique flow identifier

        Returns:
            HTTPFlow if found, None otherwise
        """
        with self._lock:
            return self._flows.get(flow_id)

    def get_all(
        self,
        offset: int = 0,
        limit: int = 100,
        method: Optional[str] = None,
        url_pattern: Optional[str] = None,
        status_code: Optional[int] = None,
    ) -> List[http.HTTPFlow]:
        """Get flows with pagination and optional filtering.

        Args:
            offset: Number of flows to skip (default 0)
            limit: Maximum flows to return (default 100)
            method: Filter by HTTP method (case-insensitive)
            url_pattern: Filter by URL regex pattern
            status_code: Filter by response status code

        Returns:
            List of HTTPFlow objects matching criteria
        """
        with self._lock:
            # Get flows in reverse order (newest first)
            all_ids = list(reversed(self._flow_order))
            flows = []

            # Compile URL pattern if provided
            url_regex = None
            if url_pattern:
                try:
                    url_regex = re.compile(url_pattern, re.IGNORECASE)
                except re.error:
                    url_regex = None

            for flow_id in all_ids:
                flow = self._flows.get(flow_id)
                if flow is None:
                    continue

                # Apply filters
                if method and flow.request.method.upper() != method.upper():
                    continue

                if url_regex and not url_regex.search(flow.request.url):
                    continue

                if status_code and (
                    flow.response is None or flow.response.status_code != status_code
                ):
                    continue

                flows.append(flow)

            # Apply pagination
            return flows[offset : offset + limit]

    def search(self, pattern: str) -> List[http.HTTPFlow]:
        """Regex search across URL, method, and status code.

        Args:
            pattern: Regex pattern to search for

        Returns:
            List of matching flows (newest first)
        """
        with self._lock:
            try:
                regex = re.compile(pattern, re.IGNORECASE)
            except re.error:
                return []

            results = []
            for flow_id in reversed(self._flow_order):
                flow = self._flows.get(flow_id)
                if flow is None:
                    continue

                # Search in URL
                if regex.search(flow.request.url):
                    results.append(flow)
                    continue

                # Search in method
                if regex.search(flow.request.method):
                    results.append(flow)
                    continue

                # Search in status code
                if flow.response and regex.search(str(flow.response.status_code)):
                    results.append(flow)
                    continue

                # Search in request headers
                for key, value in flow.request.headers.items():
                    if regex.search(key) or regex.search(value):
                        results.append(flow)
                        break
                else:
                    # Search in response headers if not found in request headers
                    if flow.response:
                        for key, value in flow.response.headers.items():
                            if regex.search(key) or regex.search(value):
                                results.append(flow)
                                break

            return results

    def clear(self) -> int:
        """Clear all stored flows.

        Returns:
            Number of flows that were cleared
        """
        with self._lock:
            count = len(self._flows)
            self._flows.clear()
            self._flow_order.clear()
            return count

    def count(self) -> int:
        """Get total number of stored flows.

        Returns:
            Current flow count
        """
        with self._lock:
            return len(self._flows)

    @property
    def max_flows(self) -> int:
        """Maximum flows that can be stored."""
        return self._max_flows


# Global storage instance - will be initialized by addon
_storage: Optional[FlowStorage] = None


def get_storage() -> FlowStorage:
    """Get the global FlowStorage instance.

    Creates a new instance if none exists.

    Returns:
        Global FlowStorage instance
    """
    global _storage
    if _storage is None:
        _storage = FlowStorage()
    return _storage


def set_storage(storage: FlowStorage) -> None:
    """Set the global FlowStorage instance.

    Args:
        storage: FlowStorage instance to use globally
    """
    global _storage
    _storage = storage
