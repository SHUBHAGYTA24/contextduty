# r/cursor Post

**Title:** I built a tool that stops Cursor from indexing your secrets — generates .cursorignore automatically + HTTPS proxy that redacts secrets from API calls

---

**Body:**

Hey all — I love Cursor but the one thing that keeps me up at night is how much context it silently sends to AI models. If you have a `config.py` with your AWS keys or a test fixture with customer data, Cursor can and will include it in context when you ask a question about nearby code.

I built **ContextDuty** to solve this. Two things it does specifically for Cursor users:

**1. Auto-generates .cursorignore**

```
contextduty protect
```

This scans your workspace, finds every file containing secrets/PII (using 25 regex detectors), and writes a `.cursorignore` file so Cursor never indexes them. It also generates ignore files for Copilot, Windsurf, Cody, etc. in case you switch tools.

Run `contextduty protect watch` and it auto-updates whenever your files change.

**2. HTTPS proxy intercepts Cursor → AI API calls**

Even if Cursor does send something sensitive (inline completions pull from open files), the proxy intercepts the request to `cursor.sh` / `api2.cursor.sh` and redacts any secrets it finds in the request body before it leaves your machine.

```
contextduty proxy start
```

It knows Cursor's JSON format — scans `messages[*].content`, `context.files[*].content`, `context.selection`, `userRequest.text`, `workspaceRootContent`.

**Also:**
- Pre-commit hook blocks secrets from entering git (so Cursor can never index them from history)
- MCP server so if you're using Cursor's MCP integration, tool responses get redacted too
- 25 detectors: AWS keys, OpenAI keys, DB connection strings, JWTs, private keys, etc.

Free, MIT, local-only, no cloud:

```
pip install contextduty
contextduty demo    # see it in 20 seconds
```

GitHub: https://github.com/SHUBHAGYTA24/contextduty

Would love feedback from Cursor power users on what else you'd want protected.
