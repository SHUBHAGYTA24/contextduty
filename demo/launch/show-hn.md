# Show HN Post

**Post on: Tuesday morning, 8-9am ET**

---

**Title:** Show HN: ContextDuty – AI context firewall that intercepts secrets before they reach any AI tool

---

**Body:**

I built ContextDuty because I watched secrets silently leak into AI tools every day at work. A teammate asked Cursor "why is this slow?" and didn't realize it sent the entire config directory — database credentials, AWS keys, everything — to OpenAI as context. No copy-paste. Invisible. Automatic.

The problem isn't careless developers. It's that AI tools decide what context to include without asking. That decision is invisible and happens dozens of times daily.

**ContextDuty protects at 5 layers:**

1. **Workspace ignore files** — one command generates .cursorignore, .copilotignore, .codeiumignore, .tabnine_ignore, .amazonq/ignore, .cody/ignore. Six AI tools blocked in one shot.

2. **Git pre-commit hook** — scans staged files. Blocks commits containing secrets. They never enter git history, so AI tools can never index them.

3. **HTTPS proxy** — sits between your machine and 21 AI API endpoints (OpenAI, Anthropic, Cursor, Copilot, Gemini, Azure, etc). Intercepts request bodies and redacts secrets in-flight. The key never leaves your machine.

4. **MCP server** — intercepts tool-call responses in Cursor/Claude before the AI model sees them.

5. **CI/CD** — fails the pipeline if secrets slip through.

**Key design decisions:**

- 100% local. No cloud service. Works air-gapped.
- 25 built-in regex detectors (AWS keys, API tokens, DSNs, PII, JWTs, private keys)
- Deterministic masks: AKIA... always becomes <AWS_KEY_1a5d44a2dc>. Same value = same mask everywhere. Audit logs are correlatable without storing raw secrets.
- Declarative config: adding support for a new AI tool = adding 3 lines. Adding a new AI API endpoint = adding field paths. Zero code changes.
- Policy-as-code with per-detector modes and inheritance.

**What it isn't:**

- Not an LLM gateway (those guard the inference call; we guard everything upstream of it)
- Not a .gitignore replacement (we generate ignore files for AI tools specifically)
- Not cloud-based PII scanning (that requires sending your data to yet another service)

258 tests. MIT licensed. Python 3.10+. No dependencies beyond stdlib for core.

pip install contextduty && contextduty demo

https://github.com/SHUBHAGYTA24/contextduty

Happy to answer questions about the architecture, the proxy interception approach, or the detector design.
