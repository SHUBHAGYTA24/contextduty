# Security Policy

ContextDuty is a security tool that reads potentially sensitive content
(secrets, PII) on users' machines. We take the security of the tool itself
seriously and welcome coordinated disclosure from the community.

## Supported versions

| Version | Supported |
|---|---|
| `1.x` (latest release) | ✅ |
| `< 1.0` | ❌ |
| `main` (unreleased) | ✅ (best effort) |

Security fixes are released as patch versions of the latest minor line.

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report privately through either channel:

1. **GitHub Security Advisory (preferred)** — open a private report at
   [Security → Report a vulnerability](https://github.com/SHUBHAGYTA24/contextduty/security/advisories/new).
   This keeps the report private and lets us collaborate on a fix.
2. **Email** — contact the maintainer at **shubhagytaswaraj@gmail.com** with
   subject line `SECURITY: ContextDuty`.

Please include:

- A description of the vulnerability and its impact
- Step-by-step reproduction (PoC where possible)
- Affected version(s) / commit
- Any suggested mitigation

## Our commitment (response targets)

| Stage | Target |
|---|---|
| Acknowledge your report | within **3 business days** |
| Initial assessment & severity triage | within **7 business days** |
| Fix or mitigation plan communicated | within **30 days** |
| Coordinated public disclosure | after a fix ships, or **90 days** from report, whichever is sooner |

These are targets, not guarantees, for a small maintainer team — but we will
keep you updated at each stage.

## Disclosure policy

We follow **coordinated disclosure**. We ask that you give us a reasonable
window (see targets above) to release a fix before any public disclosure. Once
a fix is released, we will publish a GitHub Security Advisory and, for
qualifying issues, request a **CVE** through GitHub's CNA.

## Scope

**In scope** — vulnerabilities in this repository's code, for example:

- Bypasses that cause the scanner to miss data it claims to detect in a way
  that leaks secrets/PII (e.g. the proxy forwarding unredacted content it
  should have caught)
- The proxy, MCP server, or git hook exposing, logging, or transmitting
  sensitive content it is supposed to protect
- Injection, path traversal, ReDoS, or code execution in the CLI, engine, or
  proxy
- Supply-chain integrity issues in our build/release pipeline

**Out of scope**

- Detection *recall gaps* that are inherent to pattern/NLP detection (no tool
  catches everything; see the note below). Report these as normal issues or PRs
  — they improve the product but aren't treated as vulnerabilities.
- Vulnerabilities in third-party dependencies with no exploitable path through
  ContextDuty (report those upstream; we track deps via `pip-audit` in CI).
- Social engineering, physical attacks, or issues requiring an
  already-compromised machine.

## Safe harbor

We will not pursue legal action against researchers who:

- Make a good-faith effort to avoid privacy violations, data destruction, and
  service disruption,
- Only interact with systems/accounts they own or have explicit permission to
  test, and
- Report promptly and give us reasonable time to remediate before disclosure.

## A note on detection completeness

ContextDuty reduces the risk of secrets and PII reaching AI tools; it does not
eliminate it. Like all detection tools (and as [Microsoft Presidio](https://github.com/microsoft/presidio),
our detection engine, states), **there is no guarantee that every sensitive
value will be found.** ContextDuty should be one layer of defense, not the only
one. A missed detection is a bug we want to fix, but it is not by itself a
security vulnerability.

## Recognition

With your permission, we're happy to credit you in the advisory and release
notes for responsibly disclosed issues.
