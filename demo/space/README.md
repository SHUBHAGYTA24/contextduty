---
title: ContextDuty — Local AI Prompt Firewall
emoji: 🛡️
colorFrom: indigo
colorTo: blue
sdk: gradio
sdk_version: 4.44.0
python_version: "3.11"
app_file: app.py
pinned: false
license: mit
---

# ContextDuty — local AI prompt firewall (live demo)

Paste a prompt and watch ContextDuty sanitize it **before** it would reach
Claude, Cursor, GitHub Copilot, or any AI tool. Everything runs locally on the
Space — no text is sent anywhere else.

## What you can try

- **Mode** — switch between `redact` (mask), `warn` (flag), and `block` (refuse).
- **NLP toggle + threshold** — layer local Presidio/spaCy NER on top of the
  regex detectors; drop the threshold to ~0.4 to catch phone numbers.
- **Custom detectors** — add `name = regex` rules live. The defaults catch an
  international phone number and an arbitrary document ID that pure NER misses.

## Why this isn't "just the Presidio demo"

Presidio is *one of the two detection engines* here. ContextDuty adds 60
deterministic regex detectors, a persistent policy engine (block/warn/redact +
allow/deny + custom rules), and ships as a git pre-commit hook, HTTPS proxy,
MCP server, and CLI — turning detection into **enforcement** inside a real
developer workflow.

## Run locally

```bash
pip install -r requirements.txt
python app.py
```

Project: https://github.com/SHUBHAGYTA24/contextduty
