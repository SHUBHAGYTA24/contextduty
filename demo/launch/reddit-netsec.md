# r/netsec Post

**Title:** ContextDuty: Local HTTPS proxy that intercepts and redacts secrets from AI tool API traffic (21 endpoints covered)

---

**Body:**

Released an open-source tool that addresses a gap I haven't seen covered well: secrets leaking into AI coding assistants through automatic context injection.

**The threat model:** AI coding tools (Cursor, Copilot, Windsurf, etc.) automatically index your workspace and send file contents to AI APIs as context. A developer doesn't need to copy-paste anything — the tool silently includes config files, test fixtures, and .env contents in API calls to OpenAI/Anthropic/Google.

**What ContextDuty does:**

The interesting part (from a security perspective) is the HTTPS proxy layer. It uses mitmproxy to MITM traffic between your machine and 21 AI API endpoints:

- OpenAI, Anthropic, Google (Gemini), Azure OpenAI
- Cursor, GitHub Copilot, Codeium/Windsurf
- Amazon Q, Sourcegraph Cody, Tabnine
- Cohere, Mistral, Groq, Together, Perplexity, DeepSeek, Fireworks

The proxy has a declarative "field walker" that knows exactly where each provider puts user content in their JSON request body (messages[*].content, system, context.files[*].content, etc.). It scans only those fields for 25 secret patterns and redacts in-place before the request leaves your machine.

**Other layers:**
- Generates .cursorignore/.copilotignore/.codeiumignore so tools never index sensitive files
- Pre-commit hook blocks secrets from entering git history
- MCP server intercepts tool-call responses

**Design:** 100% local. No cloud dependency. Policy-as-code. Deterministic masks (same secret = same token everywhere for audit correlation). MIT licensed.

GitHub: https://github.com/SHUBHAGYTA24/contextduty

Interested in feedback on the proxy approach and the threat model. Is anyone else seeing this as a real vector in their orgs?
