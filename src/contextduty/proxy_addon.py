"""Backward-compatible shim — imports from proxy/ package.

This file exists so that:
    1. `mitmdump -s proxy_addon.py` still works (legacy invocations)
    2. Existing tests that import from contextduty.proxy_addon continue to pass
    3. The canonical implementation lives in proxy/addon.py

Do not add new code here. Edit proxy/addon.py instead.
"""

from .proxy.addon import ContextDutyAddon, _block_response  # noqa: F401
from .proxy.scope import AI_HOSTS, PROMPT_PATHS, is_prompt_request  # noqa: F401

# These functions are imported by tests directly
_is_prompt_request = is_prompt_request


def _extract_texts(body, host):
    """Legacy wrapper — returns deduplicated list of text strings."""
    from .proxy.interceptor import extract_texts

    results = extract_texts(body, host)
    seen: set[str] = set()
    out: list[str] = []
    for text, _ in results:
        if text not in seen:
            seen.add(text)
            out.append(text)
    return out


def _inject_texts(body, texts, host):
    """Legacy wrapper — writes texts back into the body by position."""
    from .proxy.interceptor import extract_texts

    results = extract_texts(body, host)
    seen: set[str] = set()
    unique_results = []
    for text, setter in results:
        if text not in seen:
            seen.add(text)
            unique_results.append((text, setter))
    for i, (_, setter) in enumerate(unique_results):
        if i < len(texts):
            setter(texts[i])


# Entry point for `mitmdump -s proxy_addon.py`
addons = [ContextDutyAddon()]
