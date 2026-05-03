# Support

## Current Support Model

ContextDuty is an open-source project maintained by one person. There is no
paid support tier, no SLA, and no guaranteed response time.

This is stated explicitly so enterprise security and vendor risk teams can
make an informed decision.

**What you can expect:**

- GitHub Issues are reviewed regularly (typically within a few days)
- Security vulnerabilities reported via SECURITY.md are treated as highest priority
- Breaking changes will be documented in CHANGELOG.md with migration notes
- The project follows semantic versioning — patch releases do not break APIs

**What you cannot rely on for enterprise procurement today:**

- A guaranteed response SLA
- A paid support contract
- A second maintainer to cover absences
- Formal penetration testing or third-party security audit (planned, not done)

## For Enterprise Use

If you are evaluating ContextDuty for enterprise deployment, the recommended
approach is:

1. Start with a team of 5–10 engineers using a shared policy file
2. Collect audit logs to demonstrate coverage to your security team
3. Contribute improvements back — the fastest way to get enterprise-grade
   reliability is to have engineers from your org become contributors
4. Open a GitHub Discussion describing your deployment requirements — this
   directly shapes the roadmap

## Roadmap Items Relevant to Enterprise

- Audit log and `contextduty report` command — **shipped in v0.1.0**
- URL-based centralized policy distribution — **shipped in v0.1.0**
- Enterprise deployment guide — **shipped in v0.1.0** (see ENTERPRISE.md)
- Directory scanning (`contextduty scan src/`) — next milestone
- Second maintainer — open to applications via GitHub Discussions

## Security Issues

See [SECURITY.md](SECURITY.md) for the vulnerability reporting process.
