"""Tests for the proxy addon — text extraction, injection, and redaction logic."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

from contextduty.policy import Policy
from contextduty.proxy_addon import (
    ContextDutyAddon,
    _extract_texts,
    _inject_texts,
    _is_prompt_request,
)

# ---------------------------------------------------------------------------
# _is_prompt_request
# ---------------------------------------------------------------------------


def test_prompt_request_openai():
    assert _is_prompt_request("api.openai.com", "/v1/chat/completions") is True


def test_prompt_request_anthropic():
    assert _is_prompt_request("api.anthropic.com", "/v1/messages") is True


def test_prompt_request_copilot():
    assert _is_prompt_request("copilot.github.com", "/v1/engines/copilot-codex/completions") is True


def test_prompt_request_embeddings_skipped():
    # embeddings path doesn't start with a prompt path
    assert _is_prompt_request("api.openai.com", "/v1/embeddings") is False


def test_prompt_request_unknown_host():
    assert _is_prompt_request("api.stripe.com", "/v1/charges") is False


# ---------------------------------------------------------------------------
# _extract_texts — OpenAI format
# ---------------------------------------------------------------------------


def _openai_body(content):
    return {"messages": [{"role": "user", "content": content}]}


def test_extract_openai_string_content():
    body = _openai_body("tell me about user@example.com")
    texts = _extract_texts(body, "api.openai.com")
    assert texts == ["tell me about user@example.com"]


def test_extract_openai_list_content():
    body = {
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "hello"},
                    {"type": "image_url", "image_url": {"url": "http://example.com/img.png"}},
                ],
            }
        ]
    }
    texts = _extract_texts(body, "api.openai.com")
    assert texts == ["hello"]


def test_extract_openai_multiple_messages():
    body = {
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "My key is AKIAIOSFODNN7EXAMPLE"},
        ]
    }
    texts = _extract_texts(body, "api.openai.com")
    assert len(texts) == 2
    assert "AKIAIOSFODNN7EXAMPLE" in texts[1]


def test_extract_openai_legacy_prompt():
    body = {"prompt": "complete this: AKIAIOSFODNN7EXAMPLE"}
    texts = _extract_texts(body, "api.openai.com")
    assert texts == ["complete this: AKIAIOSFODNN7EXAMPLE"]


# ---------------------------------------------------------------------------
# _extract_texts — Anthropic format
# ---------------------------------------------------------------------------


def test_extract_anthropic_system_string():
    body = {
        "system": "You handle private data including user@corp.com",
        "messages": [{"role": "user", "content": "Hello"}],
    }
    texts = _extract_texts(body, "api.anthropic.com")
    assert texts[0] == "You handle private data including user@corp.com"
    assert texts[1] == "Hello"


def test_extract_anthropic_system_list():
    body = {
        "system": [{"type": "text", "text": "System: user@corp.com"}],
        "messages": [{"role": "user", "content": "Hi"}],
    }
    texts = _extract_texts(body, "api.anthropic.com")
    assert texts[0] == "System: user@corp.com"


def test_extract_anthropic_content_blocks():
    body = {
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "Key: AKIAIOSFODNN7EXAMPLE"},
                ],
            }
        ]
    }
    texts = _extract_texts(body, "api.anthropic.com")
    assert "AKIAIOSFODNN7EXAMPLE" in texts[0]


# ---------------------------------------------------------------------------
# _inject_texts — round-trip
# ---------------------------------------------------------------------------


def test_inject_openai_string():
    body = _openai_body("original text")
    _inject_texts(body, ["redacted text"], "api.openai.com")
    assert body["messages"][0]["content"] == "redacted text"


def test_inject_anthropic_system():
    body = {"system": "secret@corp.com", "messages": [{"role": "user", "content": "hi"}]}
    _inject_texts(body, ["<EMAIL_xxxx>", "hi"], "api.anthropic.com")
    assert body["system"] == "<EMAIL_xxxx>"
    assert body["messages"][0]["content"] == "hi"


def test_extract_inject_roundtrip_openai():
    body = {
        "messages": [
            {"role": "system", "content": "You are helpful."},
            {"role": "user", "content": "My key is AKIAIOSFODNN7EXAMPLE"},
        ]
    }
    texts = _extract_texts(body, "api.openai.com")
    texts[1] = texts[1].replace("AKIAIOSFODNN7EXAMPLE", "<AWS_KEY_xxxx>")
    _inject_texts(body, texts, "api.openai.com")
    assert "<AWS_KEY_xxxx>" in body["messages"][1]["content"]
    assert "AKIAIOSFODNN7EXAMPLE" not in body["messages"][1]["content"]


# ---------------------------------------------------------------------------
# ContextDutyAddon.request — integration
# ---------------------------------------------------------------------------


def _make_flow(host: str, path: str, body: dict, content_type: str = "application/json"):
    flow = MagicMock()
    flow.request.host = host
    flow.request.path = path
    flow.request.headers = {"content-type": content_type}
    flow.request.get_text.return_value = json.dumps(body)
    flow.response = None
    return flow


def _make_addon(mode: str = "redact"):
    policy = Policy(
        mode=mode,
        detectors={"aws_key", "email", "openai_key"},
        custom_detectors={},
    )
    addon = ContextDutyAddon.__new__(ContextDutyAddon)
    from contextduty.engine import scan_text

    addon._scan_text = scan_text
    addon.policy = policy
    addon.audit_log = None
    addon._findings_total = 0
    addon._requests_intercepted = 0
    return addon


def test_addon_redacts_aws_key_in_openai_request():
    aws_key = "AKIA" + "CONTEXTDUTY0DEMO"
    body = _openai_body(f"Review this config: {aws_key}")
    flow = _make_flow("api.openai.com", "/v1/chat/completions", body)
    addon = _make_addon("redact")
    addon.request(flow)

    sent_body = json.loads(flow.request.set_text.call_args[0][0])
    content = sent_body["messages"][0]["content"]
    assert aws_key not in content
    assert "<AWS_KEY_" in content
    assert flow.response is None  # not blocked


def test_addon_blocks_in_block_mode():
    aws_key = "AKIA" + "CONTEXTDUTY0DEMO"
    body = _openai_body(f"key={aws_key}")
    flow = _make_flow("api.openai.com", "/v1/chat/completions", body)
    addon = _make_addon("block")
    addon.request(flow)
    assert flow.response is not None  # blocked


def test_addon_passes_clean_request_unchanged():
    body = _openai_body("What is the weather like today?")
    flow = _make_flow("api.openai.com", "/v1/chat/completions", body)
    addon = _make_addon("redact")
    addon.request(flow)
    # set_text should NOT have been called — body is clean
    flow.request.set_text.assert_not_called()
    assert flow.response is None


def test_addon_ignores_non_ai_host():
    body = {"data": "something"}
    flow = _make_flow("api.stripe.com", "/v1/charges", body)
    addon = _make_addon("redact")
    addon.request(flow)
    flow.request.set_text.assert_not_called()


def test_addon_ignores_non_json_content_type():
    body = _openai_body("user@example.com")
    flow = _make_flow("api.openai.com", "/v1/chat/completions", body, "text/plain")
    addon = _make_addon("redact")
    addon.request(flow)
    flow.request.set_text.assert_not_called()


def test_addon_redacts_anthropic_system_prompt():
    email = "admin@secret-corp.com"
    body = {
        "system": f"You work for {email}",
        "messages": [{"role": "user", "content": "Hello"}],
    }
    flow = _make_flow("api.anthropic.com", "/v1/messages", body)
    addon = _make_addon("redact")
    addon.request(flow)

    sent_body = json.loads(flow.request.set_text.call_args[0][0])
    assert email not in sent_body["system"]
    assert "<EMAIL_" in sent_body["system"]


def test_addon_redacts_multiple_messages():
    aws_key = "AKIA" + "CONTEXTDUTY0DEMO"
    email = "user@example.com"
    body = {
        "messages": [
            {"role": "system", "content": f"Contact: {email}"},
            {"role": "user", "content": f"Key: {aws_key}"},
        ]
    }
    flow = _make_flow("api.openai.com", "/v1/chat/completions", body)
    addon = _make_addon("redact")
    addon.request(flow)

    sent_body = json.loads(flow.request.set_text.call_args[0][0])
    assert email not in sent_body["messages"][0]["content"]
    assert aws_key not in sent_body["messages"][1]["content"]


def test_addon_warn_mode_does_not_redact():
    email = "user@example.com"
    body = _openai_body(f"Contact: {email}")
    flow = _make_flow("api.openai.com", "/v1/chat/completions", body)
    addon = _make_addon("warn")
    addon.request(flow)
    # warn mode — text unchanged, not blocked
    flow.request.set_text.assert_not_called()
    assert flow.response is None
