"""Request body interceptor — walks arbitrary JSON structures to find and redact text.

This is the core logic that makes ContextDuty work for ANY AI tool, regardless
of their specific request body format. It uses a declarative field registry:
each AI tool declares where text lives in its JSON, and the interceptor walks
those paths to scan and redact.

When a new AI tool launches with a different JSON format, add entries to
PROVIDER_FIELDS. No other code changes needed.
"""

from __future__ import annotations

from typing import Any, Callable

# ─────────────────────────────────────────────────────────────────────────────
# Provider field registry — declares where text lives in each AI API's JSON.
#
# Path syntax:
#   "key"           — direct key lookup
#   "key[*]"        — iterate array at key
#   "key[*].child"  — iterate array, then access child on each element
#   "."             — current object (for nested walks)
#
# Each entry: (host_pattern, list_of_field_paths)
# host_pattern: substring match against request host
# ─────────────────────────────────────────────────────────────────────────────

PROVIDER_FIELDS: list[tuple[str, list[str]]] = [
    # ── Cursor ────────────────────────────────────────────────────────────────
    # Cursor sends workspace context in these fields (alongside standard messages)
    (
        "cursor.sh",
        [
            # Standard chat messages (Cursor uses OpenAI-compatible format)
            "messages[*].content",
            "messages[*].content[*].text",
            # Cursor-specific context fields
            "context.files[*].content",
            "context.files[*].text",
            "context.selection",
            "context.selection.text",
            "context.currentFile.content",
            "context.currentFile.text",
            "userRequest.text",
            "userRequest.message",
            "workspaceRootContent",
            "recentFiles[*].content",
            "recentFiles[*].text",
            "codeContext[*].content",
            "codeContext[*].text",
            # Tab content that Cursor sends for context
            "tabs[*].content",
            "tabs[*].text",
            # Prompt field (legacy)
            "prompt",
        ],
    ),
    # ── Anthropic / Claude ────────────────────────────────────────────────────
    (
        "anthropic",
        [
            "system",
            "system[*].text",
            "messages[*].content",
            "messages[*].content[*].text",
            # Tool results can contain sensitive data
            "messages[*].content[*].content",
            "messages[*].content[*].content[*].text",
        ],
    ),
    # ── OpenAI / Azure / Copilot ──────────────────────────────────────────────
    (
        "openai",
        [
            "messages[*].content",
            "messages[*].content[*].text",
            "prompt",
            # Function call results
            "messages[*].function_call.arguments",
            "messages[*].tool_calls[*].function.arguments",
        ],
    ),
    # ── GitHub Copilot ────────────────────────────────────────────────────────
    (
        "copilot",
        [
            "messages[*].content",
            "messages[*].content[*].text",
            "prompt",
            # Copilot sends file context
            "documents[*].content",
            "documents[*].text",
            "context[*].content",
        ],
    ),
    # ── Google Gemini ─────────────────────────────────────────────────────────
    (
        "googleapis.com",
        [
            "contents[*].parts[*].text",
            "systemInstruction.parts[*].text",
            # Grounding context
            "context.content",
        ],
    ),
    # ── Generic fallback (DeepSeek, Mistral, Groq, Together, Fireworks, Cohere)
    # Most use OpenAI-compatible format
    (
        "",  # empty string matches everything as fallback
        [
            "messages[*].content",
            "messages[*].content[*].text",
            "prompt",
            "input",
            "inputs",
        ],
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
# JSON field walker — the engine that makes declarative paths work
# ─────────────────────────────────────────────────────────────────────────────


def extract_texts(body: dict[str, Any], host: str) -> list[tuple[str, Callable[[str], None]]]:
    """Extract all text values from the request body based on the host's field registry.

    Returns a list of (text_value, setter_function) tuples.
    The setter_function can be called with redacted text to write it back.
    """
    results: list[tuple[str, Callable[[str], None]]] = []
    fields = _get_fields_for_host(host)

    for field_path in fields:
        _walk_path(body, field_path.split("."), results)

    return results


def redact_body(
    body: dict[str, Any],
    host: str,
    scan_fn: Callable[[str], Any],
) -> tuple[int, dict[str, int], bool]:
    """Scan and redact all text fields in the body in-place.

    Args:
        body: The parsed JSON request body (modified in place)
        host: The request host (determines which fields to walk)
        scan_fn: Function that takes text and returns a scan result with
                 .redacted_text, .scan.findings_count, .scan.detector_counts, .scan.blocked

    Returns:
        (total_findings, detector_counts, blocked)
    """
    texts_and_setters = extract_texts(body, host)
    total_findings = 0
    all_detector_counts: dict[str, int] = {}
    blocked = False

    for text, setter in texts_and_setters:
        if not text or not isinstance(text, str):
            continue

        result = scan_fn(text)
        total_findings += result.scan.findings_count

        for det, count in result.scan.detector_counts.items():
            all_detector_counts[det] = all_detector_counts.get(det, 0) + count

        if result.scan.blocked:
            blocked = True

        if result.redacted_text != text:
            setter(result.redacted_text)

    return total_findings, all_detector_counts, blocked


# ─────────────────────────────────────────────────────────────────────────────
# Internal path walking logic
# ─────────────────────────────────────────────────────────────────────────────


def _get_fields_for_host(host: str) -> list[str]:
    """Find the best matching field set for a host. Most specific match wins."""
    for pattern, fields in PROVIDER_FIELDS:
        if pattern and pattern in host:
            return fields
    # Fallback — return the generic fields (last entry with empty pattern)
    for pattern, fields in PROVIDER_FIELDS:
        if not pattern:
            return fields
    return []


def _walk_path(
    obj: Any,
    path_parts: list[str],
    results: list[tuple[str, Callable[[str], None]]],
) -> None:
    """Recursively walk a JSON object following the path specification."""
    if not path_parts or obj is None:
        return

    part = path_parts[0]
    remaining = path_parts[1:]

    # Handle array iteration: "key[*]"
    if part.endswith("[*]"):
        key = part[:-3]
        arr = obj.get(key) if isinstance(obj, dict) else None
        if isinstance(arr, list):
            for i, item in enumerate(arr):
                if remaining:
                    _walk_path(item, remaining, results)
                else:
                    # Terminal — this array element is the value
                    _collect_value(arr, i, item, results)
        return

    # Handle direct key access
    if isinstance(obj, dict) and part in obj:
        value = obj[part]
        if remaining:
            # More path to walk
            _walk_path(value, remaining, results)
        else:
            # Terminal — collect this value
            _collect_value(obj, part, value, results)


def _collect_value(
    container: Any,
    key: Any,
    value: Any,
    results: list[tuple[str, Callable[[str], None]]],
) -> None:
    """Collect a value and create a setter for it."""
    if isinstance(value, str) and value.strip():

        def setter(new_val: str, c=container, k=key) -> None:
            c[k] = new_val

        results.append((value, setter))
    elif isinstance(value, list):
        # Could be a list of content blocks — try to extract text from each
        for i, item in enumerate(value):
            if isinstance(item, dict) and "text" in item:
                text_val = item["text"]
                if isinstance(text_val, str) and text_val.strip():

                    def setter(new_val: str, it=item) -> None:
                        it["text"] = new_val

                    results.append((text_val, setter))
            elif isinstance(item, str) and item.strip():

                def setter(new_val: str, arr=value, idx=i) -> None:
                    arr[idx] = new_val

                results.append((item, setter))
