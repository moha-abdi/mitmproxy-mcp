"""Thin wrapper for mitmproxy script loading.

mitmproxy loads addons via file path (mitmdump -s addon.py).
This script imports from the mitmproxy_mcp package.
"""

try:
    from mitmproxy_mcp.addon import addons
except ImportError:
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from mitmproxy_mcp.addon import addons

__all__ = ["addons"]
