# Cursor Team Outreach

**To:** hi@cursor.com or security@cursor.com
**Subject:** Security tool built specifically for Cursor — would love to get listed

---

Hi Cursor team,

I'm a Cursor user who built an open-source security tool specifically for the problem of secrets leaking through AI context. Would love to get ContextDuty listed in your security integrations or docs.

**What it does:**

ContextDuty auto-generates a `.cursorignore` file by scanning your workspace for secrets (AWS keys, API tokens, database credentials, private keys — 25 detectors). Files containing secrets are blocked from Cursor's indexer.

It also has an HTTPS proxy layer that intercepts traffic to `cursor.sh` and `api2.cursor.sh` — it knows Cursor's JSON request format and redacts secrets from `messages[*].content`, `context.files[*].content`, `context.selection`, `userRequest.text`, and `workspaceRootContent` before the request leaves the developer's machine.

**Why it matters for Cursor:**

Cursor enterprise customers need to prove to their security teams that AI tools don't exfiltrate credentials. Right now there's no standard answer for that. ContextDuty gives them a concrete, auditable solution — which removes a blocker to adopting Cursor at regulated companies.

**What I'm asking:**

A mention in the Cursor docs (security section), a tweet, or a listing in any partner/integration page you maintain. Happy to write a guest blog post on "securing your Cursor workspace."

GitHub: https://github.com/SHUBHAGYTA24/contextduty
pip install contextduty && contextduty demo

Thanks,
Shubhagyta
