"""ContextDuty live demo — Gradio app (Hugging Face Space ready).

Unlike a plain "paste text, see PII" box, this demonstrates what ContextDuty
actually is: a *policy-driven firewall* that combines 60 deterministic regex
detectors with local Presidio/spaCy NLP, and lets you choose what happens to
each finding — redact, warn, or block — plus add your own custom rules on the
fly. Everything runs locally; no text leaves the machine it runs on.
"""

from __future__ import annotations

import json

import gradio as gr

from contextduty.detectors import DETECTORS
from contextduty.engine import scan_text
from contextduty.policy import Policy

try:
    from contextduty.nlp._scanner import get_backend, scan_text_nlp

    _NLP_OK = True
    _BACKEND = get_backend()
except Exception:  # pragma: no cover - NLP optional
    _NLP_OK = False
    _BACKEND = "unavailable"

_ALL_DETECTORS = sorted(d.name for d in DETECTORS)

_EXAMPLE = (
    "Hi, this is David. Reach me at +91-76223980909 or david.lee@acme.co.\n"
    "My card is 4111111111111111, SSN 123-45-6789.\n"
    "Document number Abafdj4355 is required for my visa.\n"
    'aws_key="AKIA1234567890ABCDEF"'
)


def _parse_custom(text: str) -> dict[str, str]:
    """Parse 'name = regex' lines into a custom_detectors dict."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, _, pattern = line.partition("=")
        name, pattern = name.strip(), pattern.strip()
        if name and pattern:
            out[name] = pattern
    return out


def analyze(text, mode, use_nlp, confidence, custom_text):
    custom = _parse_custom(custom_text or "")
    detectors = set(_ALL_DETECTORS) | set(custom)
    policy = Policy(mode=mode, detectors=detectors, custom_detectors=custom)

    try:
        result = scan_text(text, policy)
    except Exception as exc:  # invalid custom regex etc.
        return f"⚠️ {exc}", [], "{}"

    rows = []
    for det, count in sorted(result.scan.detector_counts.items()):
        rows.append([det, "regex", count, "—"])

    nlp_note = ""
    if use_nlp and _NLP_OK:
        try:
            nlp = scan_text_nlp(text, min_confidence=confidence, extract_segments=False)
            agg: dict[str, list] = {}
            for f in nlp.findings:
                a = agg.setdefault(f.detector_name, [0, 0.0])
                a[0] += 1
                a[1] = max(a[1], f.confidence)
            for det, (count, conf) in sorted(agg.items()):
                rows.append([det, "nlp", count, f"{conf:.2f}"])
        except Exception as exc:
            nlp_note = f"\n(NLP error: {exc})"
    elif use_nlp:
        nlp_note = "\n(NLP backend not installed in this Space)"

    verdict = (
        "🚫 BLOCKED"
        if result.scan.blocked
        else ("🟡 findings (warn)" if result.scan.findings_count else "✅ clean")
    )
    header = f"{verdict} — backend: {_BACKEND}{nlp_note}\n\n"
    summary = json.dumps(
        {
            "findings_count": result.scan.findings_count,
            "blocked": result.scan.blocked,
            "blocked_by": result.scan.blocked_by,
        },
        indent=2,
    )
    return header + result.redacted_text, rows, summary


with gr.Blocks(title="ContextDuty — local AI prompt firewall") as demo:
    gr.Markdown(
        "# ContextDuty — local prompt firewall\n"
        "60 regex detectors **+** local Presidio/spaCy NLP, with a policy you "
        "control. Choose **redact / warn / block**, tune the NLP threshold, and "
        "add your own rules — then watch the prompt get sanitized before it "
        "would ever reach Claude, Cursor, or Copilot. 100% local."
    )
    with gr.Row():
        with gr.Column():
            inp = gr.Textbox(value=_EXAMPLE, lines=8, label="Prompt / text")
            with gr.Row():
                mode = gr.Radio(["redact", "warn", "block"], value="redact", label="Mode")
                use_nlp = gr.Checkbox(value=_NLP_OK, label=f"Use NLP ({_BACKEND})")
            confidence = gr.Slider(0.0, 1.0, value=0.4, step=0.05, label="NLP confidence threshold")
            _custom_default = (
                "intl_phone = \\+\\d{1,3}-?\\d{7,12}\n"
                "doc_number = \\b[A-Za-z]{4,6}\\d{3,6}\\b"
            )
            custom = gr.Textbox(
                value=_custom_default,
                lines=3,
                label="Custom detectors (name = regex, one per line)",
            )
            btn = gr.Button("Scan", variant="primary")
        with gr.Column():
            out = gr.Textbox(lines=8, label="Result (redacted)")
            table = gr.Dataframe(
                headers=["detector", "layer", "count", "max_conf"],
                label="Findings",
                wrap=True,
            )
            summary = gr.Code(label="Summary", language="json")

    btn.click(analyze, [inp, mode, use_nlp, confidence, custom], [out, table, summary])
    gr.Markdown(
        "**How this differs from the Presidio demo:** Presidio is one of the two "
        "detection engines here. ContextDuty adds 60 deterministic regex "
        "detectors, a persistent **policy** (block/warn/redact + allow/deny + "
        "custom rules), and ships as a git pre-commit hook, HTTPS proxy, MCP "
        "server, and CLI — so detection becomes *enforcement* in your real "
        "workflow. The custom rules above catch the international phone and ID "
        "number that NER alone misses."
    )


if __name__ == "__main__":
    demo.launch()
