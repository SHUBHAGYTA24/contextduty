# ContextDuty for Teams — the pitch (plain English)

## The one line

> **See whether your developers are actually protected from leaking secrets to
> AI tools — without ever seeing their code.**

## The problem (in one breath)

Your developers use Cursor, Copilot, and ChatGPT all day. Sometimes they paste
a real API key, a password, or customer data into a prompt. It leaves the
company the moment they hit enter. You have no idea when it happens.

You *could* put a tool on every laptop to catch it. But two problems:

1. **You can't tell if it's actually on.** A developer can turn it off, skip it
   with `git commit --no-verify`, or never install it — and you'd never know.
2. **The tools that give you visibility are cloud tools** — they send your
   developers' code and prompts to a third-party server to inspect. For a bank
   or a hospital, that's a non-starter.

## What ContextDuty for Teams does

Think of it like a **smoke-detector network** for your engineering org.

- Every developer's machine runs the free ContextDuty tool (blocks secrets in
  git, IDE, and AI traffic).
- Each machine sends a tiny "I'm here and working" ping to **one dashboard you
  run inside your own network**.
- The dashboard shows you, at a glance:
  - **Coverage** — "247 of 250 laptops protected; 3 went dark since Tuesday."
  - **Prevented leaks** — "1,432 secrets stopped this quarter."
  - **Bypasses** — "Alex used `--no-verify` on the payments repo yesterday."

## The one thing that makes this different

**The pings contain no code and no secrets — only counts.**

Never the secret. Never the file. Never the prompt. Just numbers like
*"3 AWS keys blocked"* and *"this laptop is running."* So you get the visibility
a security team needs, and the data **never leaves your network**.

Cloud DLP tools (Nightfall, Cyberhaven, LayerX) **can't** say that — inspecting
the data is how they work. That's our whole edge.

## Why a CISO cares

- **Compliance:** frameworks accept "we can *see* when a control is bypassed."
  You get an audit trail without an audit risk.
- **A number for the board:** "we prevented N credential leaks this quarter."
- **Zero data exposure:** self-hosted, single-tenant, metadata-only.

## How it's sold

- The developer tool is **free and open-source** — that's what gets it onto
  laptops.
- The **team dashboard** (fleet visibility, bypass alerts, prevention reports,
  central policy) is the paid part. Runs in your cloud; we can manage a
  dedicated instance for you.

## The 60-second demo

Run this and talk through it:

```bash
bash demo/team_demo.sh
```

It will, live in front of them:

1. Start the **fleet dashboard** (their own, on localhost).
2. Enroll a repo and make a **normal commit** → the dashboard shows a protected,
   reporting endpoint.
3. Make a **`git commit --no-verify`** (a bypass) → within a second, a **red
   tamper event** appears on the dashboard: *"bypass — git commit --no-verify."*
4. Point at the store file and show them: **only counts and hostnames — no code,
   no secrets.**

The "aha" is step 3 → 4: *"You just watched me sneak a commit past the guard,
and your dashboard caught it — and still never saw a line of my code."*

## If they ask…

- **"Can a developer just uninstall it?"** Yes — you can't make an endpoint
  control unbreakable (they own the machine). But you can make bypass
  **visible**, which is what you actually need. And for a hard stop, the same
  engine runs server-side in your git (nothing to bypass there).
- **"What exactly leaves the laptop?"** A hostname, a username, which surfaces
  are on, a policy fingerprint, and detector *counts*. That's it. It's
  open-source — your team can read the exact code that decides.
- **"Is our data multi-tenant with other customers?"** No. Single-tenant. Your
  instance, your network, your data only.
