"""Tests for the declarative JSON field walker (interceptor.py)."""

from __future__ import annotations

from contextduty.interceptor import (
    _get_fields_for_host,
    extract_texts,
    redact_body,
)

# ---------------------------------------------------------------------------
# Field registry resolution
# ---------------------------------------------------------------------------


def test_get_fields_cursor():
    fields = _get_fields_for_host("api2.cursor.sh")
    assert "context.files[*].content" in fields
    assert "userRequest.text" in fields


def test_get_fields_anthropic():
    fields = _get_fields_for_host("api.anthropic.com")
    assert "system" in fields
    assert "messages[*].content" in fields


def test_get_fields_openai():
    fields = _get_fields_for_host("api.openai.com")
    assert "messages[*].content" in fields
    assert "prompt" in fields


def test_get_fields_google():
    fields = _get_fields_for_host("generativelanguage.googleapis.com")
    assert "contents[*].parts[*].text" in fields


def test_get_fields_unknown_uses_fallback():
    fields = _get_fields_for_host("api.somenewai.com")
    assert "messages[*].content" in fields
    assert "prompt" in fields


# ---------------------------------------------------------------------------
# extract_texts — Cursor format
# ---------------------------------------------------------------------------


def test_extract_cursor_context_files():
    body = {
        "context": {
            "files": [
                {"path": "config.py", "content": "AWS_KEY=AKIAEXAMPLE123456"},
                {"path": "app.py", "content": "print('hello')"},
            ]
        },
        "messages": [{"role": "user", "content": "explain this code"}],
    }
    results = extract_texts(body, "api2.cursor.sh")
    texts = [t for t, _ in results]
    assert "AWS_KEY=AKIAEXAMPLE123456" in texts
    assert "print('hello')" in texts
    assert "explain this code" in texts


def test_extract_cursor_selection():
    body = {
        "context": {"selection": "password = 's3cr3t_admin_pass'"},
        "messages": [{"role": "user", "content": "refactor this"}],
    }
    results = extract_texts(body, "api2.cursor.sh")
    texts = [t for t, _ in results]
    assert "password = 's3cr3t_admin_pass'" in texts


def test_extract_cursor_user_request():
    body = {
        "userRequest": {"text": "fix the bug in config with key AKIAEXAMPLE123456"},
    }
    results = extract_texts(body, "api2.cursor.sh")
    texts = [t for t, _ in results]
    assert "fix the bug in config with key AKIAEXAMPLE123456" in texts


def test_extract_cursor_workspace_root():
    body = {
        "workspaceRootContent": "DB_URL=postgres://admin:pass@host/db",
    }
    results = extract_texts(body, "api2.cursor.sh")
    texts = [t for t, _ in results]
    assert "DB_URL=postgres://admin:pass@host/db" in texts


# ---------------------------------------------------------------------------
# extract_texts — Google Gemini format
# ---------------------------------------------------------------------------


def test_extract_google_gemini():
    body = {
        "contents": [
            {"parts": [{"text": "my key is AKIAEXAMPLE123456"}]},
        ],
        "systemInstruction": {
            "parts": [{"text": "you are a helper"}],
        },
    }
    results = extract_texts(body, "generativelanguage.googleapis.com")
    texts = [t for t, _ in results]
    assert "my key is AKIAEXAMPLE123456" in texts
    assert "you are a helper" in texts


# ---------------------------------------------------------------------------
# extract_texts — standard OpenAI
# ---------------------------------------------------------------------------


def test_extract_openai_messages():
    body = {
        "messages": [
            {"role": "system", "content": "You are helpful."},
            {"role": "user", "content": "My AWS key is AKIAEXAMPLE123456"},
        ]
    }
    results = extract_texts(body, "api.openai.com")
    texts = [t for t, _ in results]
    assert "You are helpful." in texts
    assert "My AWS key is AKIAEXAMPLE123456" in texts


def test_extract_openai_content_blocks():
    body = {
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "check this key AKIAEXAMPLE"},
                    {"type": "image_url", "image_url": {"url": "http://x.com/a.png"}},
                ],
            }
        ]
    }
    results = extract_texts(body, "api.openai.com")
    texts = [t for t, _ in results]
    assert "check this key AKIAEXAMPLE" in texts


# ---------------------------------------------------------------------------
# Setter functions — verify in-place modification works
# ---------------------------------------------------------------------------


def test_setter_modifies_body_in_place():
    body = {"messages": [{"role": "user", "content": "secret: AKIAEXAMPLE123456"}]}
    results = extract_texts(body, "api.openai.com")
    for text, setter in results:
        if "AKIA" in text:
            setter("<REDACTED>")
    assert body["messages"][0]["content"] == "<REDACTED>"


def test_setter_cursor_context_files():
    body = {
        "context": {
            "files": [
                {"path": "x.py", "content": "key=AKIAEXAMPLE123456"},
            ]
        }
    }
    results = extract_texts(body, "api2.cursor.sh")
    for text, setter in results:
        if "AKIA" in text:
            setter("<REDACTED>")
    assert body["context"]["files"][0]["content"] == "<REDACTED>"


def test_setter_google_gemini():
    body = {
        "contents": [{"parts": [{"text": "key=AKIAEXAMPLE123456"}]}],
    }
    results = extract_texts(body, "generativelanguage.googleapis.com")
    for text, setter in results:
        if "AKIA" in text:
            setter("<REDACTED>")
    assert body["contents"][0]["parts"][0]["text"] == "<REDACTED>"


# ---------------------------------------------------------------------------
# redact_body — integration with scan engine
# ---------------------------------------------------------------------------


def test_redact_body_cursor_full():
    """End-to-end: Cursor body with secrets gets redacted in-place."""
    from contextduty.engine import scan_text
    from contextduty.policy import load_policy

    aws_key = "AKIA" + "IOSFODNN7EXAMPLE"
    body = {
        "context": {
            "files": [
                {"path": "config.env", "content": f"AWS_KEY={aws_key}"},
                {"path": "app.py", "content": "print('hello')"},
            ]
        },
        "messages": [{"role": "user", "content": "explain this"}],
    }

    policy = load_policy(None)

    def scan_fn(text):
        return scan_text(text, policy)

    findings, det_counts, blocked = redact_body(body, "api2.cursor.sh", scan_fn)
    assert findings > 0
    assert "aws_key" in det_counts
    # The AWS key should be redacted in-place
    assert aws_key not in body["context"]["files"][0]["content"]
    assert "<AWS_KEY_" in body["context"]["files"][0]["content"]
    # Clean file untouched
    assert body["context"]["files"][1]["content"] == "print('hello')"


def test_redact_body_clean_passes_through():
    from contextduty.engine import scan_text
    from contextduty.policy import load_policy

    body = {
        "messages": [{"role": "user", "content": "what is 2+2?"}],
    }
    policy = load_policy(None)

    def scan_fn(text):
        return scan_text(text, policy)

    findings, det_counts, blocked = redact_body(body, "api.openai.com", scan_fn)
    assert findings == 0
    assert det_counts == {}
    assert not blocked
