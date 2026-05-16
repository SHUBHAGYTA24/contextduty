# Anthropic MCP Marketplace Submission

**Submit at:** https://github.com/modelcontextprotocol/servers (open a PR to add to the list)
**Also submit at:** https://glama.ai/mcp/servers (form submission)

---

## Server listing details

**Name:** ContextDuty

**Category:** Security / Privacy

**Short description:**
AI context firewall — scans and redacts secrets from MCP tool responses before they reach the AI model.

**Full description:**
ContextDuty is a local MCP server that intercepts tool-call responses and removes secrets, API keys, and PII before the AI model ever sees them.

When an AI agent calls a tool (read_file, query_database, fetch_url), the result often contains sensitive data the developer didn't intend to expose. ContextDuty sits in the MCP chain and redacts that data in-place using 25 built-in regex detectors.

**What it catches:**
- API keys: AWS, OpenAI, Anthropic, GitHub, Stripe, Slack, Sendgrid, HuggingFace, Twilio, Azure, GCP
- PII: emails, phone numbers
- Database credentials (connection strings with embedded passwords)
- Cryptographic material: SSH private keys, PGP keys, JWTs
- Generic tokens and bearer tokens

**Key properties:**
- 100% local — nothing leaves your machine
- Deterministic masks: same secret = same token (audit-correlatable)
- Policy-as-code: configure per-detector modes, allow-patterns, custom regexes
- Works with Cursor, Claude Desktop, VS Code, any MCP-compatible client

**Install:**
```bash
pip install contextduty
```

**Config for Cursor (`~/.cursor/mcp.json`):**
```json
{
  "mcpServers": {
    "contextduty": {
      "command": "contextduty-mcp"
    }
  }
}
```

**Config for Claude Desktop (`~/.claude/claude_desktop_config.json`):**
```json
{
  "mcpServers": {
    "contextduty": {
      "command": "contextduty-mcp"
    }
  }
}
```

**Repository:** https://github.com/SHUBHAGYTA24/contextduty
**License:** MIT
**Python:** 3.10+

---

## modelcontextprotocol/servers PR

Add to README.md under "Security" category:

```markdown
- **[ContextDuty](https://github.com/SHUBHAGYTA24/contextduty)** - AI context firewall. Scans and redacts secrets from tool responses before they reach the AI model. 25 built-in detectors, policy-as-code, 100% local.
```
