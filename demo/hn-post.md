# Hacker News — Show HN post

---

**Title:**
Show HN: ContextDuty – blocks secrets from entering AI context before the prompt is assembled

---

**Body:**

I built ContextDuty after watching a teammate ask Cursor to "review this function" — and realising the entire `config/` directory, including production database credentials and an OpenAI key, had silently been sent to OpenAI as context. He didn't paste anything. Cursor indexed it automatically.

The problem isn't that developers are reckless. The problem is that AI coding tools make the decision about what to include in context, not the developer. That decision is invisible, instantaneous, and happens dozens of times per day.

**What ContextDuty does:**

Three enforcement layers, all local, zero dependencies:

1. **Pre-commit hook** — scans staged files before `git commit` completes. If an AWS key or OpenAI token is found in block mode, the commit is rejected. Secret never enters git history. Cursor can never index it.

2. **MCP interception** — runs as an MCP server alongside Cursor/Claude. When an AI agent calls a tool (read_file, query_db), ContextDuty intercepts the response before the agent sees it. The agent receives `<AWS_KEY_1a5d44a2dc>` instead of `AKIAIOSFODNN7EXAMPLE`. Real value never enters the prompt.

3. **CI/CD scan** — `contextduty scan src/` in your pipeline. Block mode exits non-zero on findings. PR cannot merge.

**Try it:**

```bash
pip install contextduty
contextduty demo
```

The demo runs five scenes locally in about 20 seconds — no git repo needed, no config file, no signup. Creates a fake config with realistic-looking credentials, scans it, redacts it, runs a real pre-commit hook against it, then cleans up.

**What I've learned building this:**

The "enterprise agreement" objection comes up immediately. Customers assume that because they signed an OpenAI Enterprise agreement (no training on their data), they're safe. The agreement protects them from OpenAI *deliberately* using their data. It doesn't protect them if OpenAI is breached. HIPAA and PCI-DSS don't care about vendor contracts — the fine lands on the data controller regardless.

The second objection: "we can just train developers." Samsung trained their developers. A Samsung engineer still pasted proprietary semiconductor source code into ChatGPT in April 2023. Training tells people what not to do. ContextDuty makes it technically impossible to do by accident.

**What's missing and what's next:**

The remaining gap is Cursor/Copilot's native context-pulling over HTTPS. A VS Code extension can't intercept another extension's network traffic — they're sandboxed from each other. The only real solution is a local HTTPS proxy (same technique Zscaler uses, except running on the developer's machine so nothing reaches a third-party inspection service). That's the next build.

**Detection coverage:**

25 built-in detectors — AWS, GCP, GitHub PAT, OpenAI, Anthropic, HuggingFace, Slack, Stripe, SendGrid, Twilio, Azure, database DSNs (only when credentials are embedded), SSH/PGP private keys, JWTs, generic `.env` secrets, email, phone. Policy-as-code in `.contextduty.json` with `extends` for team baselines. Custom detectors via regex. Per-detector modes (block API keys, warn on email). Allow patterns to whitelist known-safe values like `@testdata.internal`.

Masks are deterministic: the same value always produces the same mask token. `AKIAIOSFODNN7EXAMPLE` is always `<AWS_KEY_1a5d44a2dc>`. This means you can correlate findings across audit log entries and across files without ever storing the raw secret.

**Audit log:**

Every scan appends a JSONL entry — timestamp, operation, target, hostname, user, finding counts, detector names, whether it was blocked. Never the raw values. That log is what you show the HIPAA auditor to prove your controls ran.

Source: https://github.com/SHUBHAGYTA24/contextduty

Happy to answer questions about the detection engine, the MCP interception layer, or the proxy approach.

---

# Dev.to / Blog article

**Title: Your AI coding assistant is leaking your secrets. Here's how we're stopping it.**

---

Last month I watched a teammate trigger a HIPAA near-miss without doing anything wrong.

He was debugging a slow database query. He opened Cursor, asked "why is this function slow?", and got a good answer. What he didn't see was the context panel — Cursor had automatically included `config/database.yml` (production credentials), `tests/fixtures/customers.json` (real patient emails from a staging sync), and `.env.local` (six API keys). All of it silently sent to OpenAI.

He didn't paste anything. He didn't make a mistake. Cursor made the context decision for him, invisibly.

This is the new threat surface. Not phishing. Not misconfigured S3 buckets. **AI tools that autonomously decide what data to include in a cloud API call.**

---

## Why existing tools miss it

**LLM gateways** (Portkey, LiteLLM, Helicone) intercept at the inference call — after Cursor has already assembled the prompt and sent it over HTTPS. By the time the gateway sees it, the secret has already left your environment, traveled through the network, and arrived at the gateway's infrastructure. Blocking it there is better than nothing. It's not early enough.

**DLP tools** (Zscaler, Netskope) catch HTTPS traffic but were built for email and USB drives. They weren't designed for AI assistant workflows and they send your traffic to their cloud for inspection — which means your prompts go from OpenAI's servers to Zscaler's servers. You traded one third-party for another.

**Presidio** is a Python library that detects PII in text. It's excellent at what it does. But it only runs when you explicitly call it. It has no git hooks, no CI integration, no block mode. If nobody calls it before the prompt is assembled, it doesn't help.

**Training developers** doesn't scale. Samsung tried it. In April 2023, a Samsung engineer pasted proprietary semiconductor source code into ChatGPT. Internationally reported. Training tells people what not to do. It doesn't change the fact that Cursor makes context decisions automatically, faster than any developer can audit.

---

## What actually works: enforce earlier

The secret that reaches OpenAI was in your codebase first. It was in a file. That file was staged for commit. It could have been caught there — three steps before any AI tool ever saw it.

That's the design principle behind ContextDuty: **enforce at the point of origin, not at the point of transmission.**

Three layers:

**Layer 1 — Git pre-commit hook**

```bash
contextduty install-hooks
```

Every `git commit` now triggers a scan of staged files. AWS key in `config.py`? Commit blocked. The key never enters git history. Cursor cannot index what doesn't exist in the repo.

**Layer 2 — MCP interception**

Add ContextDuty to your MCP config (Cursor, Claude, VS Code):

```json
{
  "mcpServers": {
    "contextduty": { "command": "contextduty-mcp" }
  }
}
```

When an AI agent calls `read_file("customers.json")`, ContextDuty intercepts the tool response before the agent sees it. The agent receives `{"email": "<EMAIL_459d753cb7>"}` instead of the real address. The real value never enters the context window. Never reaches OpenAI.

**Layer 3 — CI/CD**

```yaml
- run: contextduty scan src/ --policy .contextduty.json
```

Set `"mode": "block"` and the pipeline fails if anything slips through. PR cannot merge.

---

## The detection engine

25 built-in detectors: AWS access keys, OpenAI/Anthropic/HuggingFace tokens, GitHub PATs, Stripe/Slack/Twilio/SendGrid keys, database DSNs (only when credentials are embedded), SSH/PGP private keys, JWTs, generic `.env` secrets, email, phone.

Masks are **deterministic**. The same value always produces the same mask:

```
AKIAIOSFODNN7EXAMPLE  →  <AWS_KEY_1a5d44a2dc>   (always)
jane@corp.com         →  <EMAIL_459d753cb7>       (always)
```

This means you can correlate findings across audit log entries without ever storing raw secrets. The audit log itself never contains real values — only finding counts, detector names, timestamps, and whether the scan was blocked.

---

## The remaining gap

One gap I'm being upfront about: Cursor's native context-pulling over HTTPS.

When Cursor autonomously indexes your workspace and assembles context for a chat message, that happens in Cursor's own process over a direct HTTPS connection to OpenAI. A VS Code extension can't intercept another extension's network traffic — they're sandboxed. The pre-commit hook stops secrets from being in the repo in the first place, which closes most of this gap. But if secrets already exist in the repo, the MCP layer is the next catch. If the developer is using Cursor's native chat (not an MCP tool), the only remaining option is a local HTTPS proxy.

That's what I'm building next. Local proxy using mitmproxy as the foundation, running on the developer's machine. Intercepts all traffic to `api.openai.com`, `api.anthropic.com`, `copilot.github.com`. Runs ContextDuty's scan engine on the request body. Redacts before forwarding. Nothing leaves the machine for inspection — not even to us.

The differentiator vs Zscaler: their proxy inspects your traffic on Zscaler's infrastructure. This proxy inspects on your device. For hospitals and banks operating in regulated environments, that's not optional — it's the only architecture that's viable.

---

## Try it

```bash
pip install contextduty
contextduty demo
```

The demo creates a fake config with realistic-looking credentials, scans it, redacts it, fires a real pre-commit hook, scans a directory of fake customer PII. Runs in about 20 seconds. Nothing leaves your machine.

Source: https://github.com/SHUBHAGYTA24/contextduty

The proxy is in active development. If you're at a company where this is a live problem — particularly healthcare, fintech, or anywhere with a compliance requirement — I'd like to hear what your actual workflow looks like and what the proxy needs to handle.

---
