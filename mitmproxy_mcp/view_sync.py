from typing import Any, Optional, Set

from mitmproxy import ctx


VIEW_SYNC_ACTIONS = {"replay", "clear"}


def parse_view_sync_actions(raw_value: str) -> Set[str]:
    value = raw_value.strip().lower()

    if value == "all":
        return set(VIEW_SYNC_ACTIONS)
    if value == "none":
        return set()
    if not value:
        raise ValueError(
            "mcp_view_sync_actions cannot be empty. Use one of: all, none, replay, clear, replay,clear"
        )

    tokens = [token.strip() for token in value.split(",")]
    if any(not token for token in tokens):
        raise ValueError(
            "mcp_view_sync_actions contains empty entries. Use comma-separated actions like replay,clear"
        )

    actions = set(tokens)
    invalid = sorted(action for action in actions if action not in VIEW_SYNC_ACTIONS)
    if invalid:
        raise ValueError(
            f"Invalid mcp_view_sync_actions value: {', '.join(invalid)}. Allowed actions: replay, clear, all, none"
        )

    return actions


def should_sync_action(action: str, options: Optional[Any] = None) -> bool:
    if action not in VIEW_SYNC_ACTIONS:
        return False

    if options is None:
        options = getattr(ctx, "options", None)
    if options is None:
        return False

    raw_value = getattr(options, "mcp_view_sync_actions", "all")
    if not isinstance(raw_value, str):
        return False

    try:
        actions = parse_view_sync_actions(raw_value)
    except ValueError:
        return False

    return action in actions
