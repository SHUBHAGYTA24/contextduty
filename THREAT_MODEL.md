# Threat Model & Security Assessment

This is ContextDuty's security assessment: the most likely and impactful
security problems, and how the project addresses them. It complements
[ARCHITECTURE.md](ARCHITECTURE.md) (actors, components, data flows) and
[SECURITY.md](SECURITY.md) (reporting).

## Assets to protect

1. **Users' sensitive content** — the secrets and PII ContextDuty scans. The
   overriding property: **this content must never leave the user's machine**
   except as redacted output the user intends to send.
2. **Integrity of the tool** — a compromised ContextDuty could silently pass
   secrets through, so the distributed artifact's integrity matters.
3. **Users' trust boundary** — the proxy and hook sit inline in sensitive flows
   (traffic, commits); they must not weaken existing protections.

## Primary threats and mitigations

| # | Threat | Impact | Mitigation |
|---|---|---|---|
| T1 | ContextDuty **exfiltrates** scanned content (telemetry, phone-home) | Critical — breaks core promise | No network egress of content; audit log is metadata-only; fully local; source is auditable (OSS). |
| T2 | Proxy **disables upstream TLS verification**, enabling MITM of the user's AI traffic | High | Upstream TLS verification is kept ON (no `--ssl-insecure`); proxy binds to `127.0.0.1` only. |
| T3 | Scanner **misses** a secret and forwards it unredacted (false negative) | High | Layered detection (regex + NLP); block mode; tests per detector; benchmark; documented as defense-in-depth, not a guarantee. |
| T4 | **Supply-chain compromise** of the published package | Critical | PyPI OIDC trusted publishing (no long-lived token); Sigstore-signed releases; SBOM per release; `pip-audit` in CI. |
| T5 | **Malicious PR** introduces a backdoor or weakens detection | High | Branch protection (PR required on `main`); CI must pass; maintainer review; CLA; least-privileged CI tokens. |
| T6 | Secrets **committed to this repo** by mistake | Medium | ContextDuty scans itself in CI; pre-commit hook; `.gitignore`; GitHub secret scanning. |
| T7 | **ReDoS** via a crafted input to a detector regex | Medium | Line-length cap (`MAX_LINE_LEN`) skips oversized lines; bounded quantifiers in patterns. |
| T8 | **Shell/command injection** through the generated git hook (paths with metacharacters) | Medium | Values embedded in the hook are bash-double-quote-escaped (`_bash_dq_escape`). |
| T9 | Malformed policy/`extends` causes crash or unexpected enforcement | Low/Medium | Typed validation, cycle detection, `policy validate --strict` (run on the repo's own policy in CI). |
| T10 | **Bypass** of a client-side control (`--no-verify`, stopping the proxy) | Medium (accepted) | Endpoint controls are voluntary by nature; the roadmap addresses this with server-side choke points and metadata-only visibility (never content). |

## Trust boundaries

- **The machine** is the boundary; unredacted content never crosses it.
- **Untrusted inputs**: AI-tool request bodies, files being scanned, and PR
  contributions. These are parsed defensively and reviewed before merge.
- **Privileged operations** (publish, sign) run only on maintainer-pushed tags,
  isolated from fork-PR execution.

## Residual risk / non-goals

- **Detection is not exhaustive.** No pattern/NLP system catches every secret or
  PII value; ContextDuty is one layer of defense (see [SECURITY.md](SECURITY.md)).
- **Endpoint controls are bypassable** by the machine's owner by design; making
  bypass *observable* (metadata-only) and adding server-side enforcement is a
  roadmap item, not a current guarantee.
- **The HTTPS proxy requires a local CA** and is labeled the most advanced /
  least frictionless surface; users who cannot accept a local CA should rely on
  the hook, IDE-ignore, MCP, and CI surfaces.

## Assessment method & cadence

This assessment is maintained by the project maintainer, reviewed on each
security-relevant change and at each minor release. Findings are tracked as
issues (or private advisories for vulnerabilities) and mitigations land via PR
with tests where applicable.
