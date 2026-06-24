# ContextDuty — market need, moat, and positioning vs Presidio

> Honest internal analysis. ContextDuty uses **Microsoft Presidio** as its
> detection brain. This document explains why a product still exists *on top*
> of Presidio, what the defensible moat actually is (and is not), and a rough
> sizing of the opportunity.

## 1. The problem is real and growing fast

| Signal | Source |
|---|---|
| **34.8%** of data submitted to AI tools is sensitive (2026) — up from **11%** in 2023 | [Cyberhaven Labs, 7M knowledge workers](https://aona.ai/blog/ai-data-loss-prevention/) |
| Enterprise AI usage grew **4.6× YoY**; **83.8%** of enterprise AI traffic to external tools is medium/high/critical risk | [Cyberhaven Labs](https://www.lasso.security/blog/llm-data-privacy) |
| 4.7% of employees had pasted confidential data into ChatGPT; 11% of pasted data was confidential (2023 baseline) | [Cyberhaven, 1.6M workers](https://www.cobalt.io/blog/llm-data-leakage-10-best-practices) |
| Samsung banned all generative AI after engineers pasted **semiconductor source code** into ChatGPT | [multiple, 2023](https://intuitionlabs.ai/articles/prevent-chatgpt-proprietary-data-leaks) |
| "Traditional DLP was never designed to handle data flows through AI systems" | [Aona AI](https://aona.ai/blog/ai-data-loss-prevention/) |

**Takeaway:** the leak surface moved from "code in a repo" to "text in a prompt
typed into a third-party AI tool." That surface is exploding and legacy DLP
doesn't see it. Demand is not the question — differentiation is.

## 2. The competitive landscape (where Presidio sits)

| Category | Examples | What it is | Gaps for our use case |
|---|---|---|---|
| **Detection/anonymization library** | **Microsoft Presidio** | Best-in-class local PII NER + regex + operators; library/Docker/K8s/REST/Spark | Not a workflow product — you assemble the enforcement yourself; no git/IDE/proxy/MCP |
| **Cloud DLP for AI** | Aona, Lasso, Nightfall | SaaS, browser/network DLP across 5,000+ AI tools | Paid, per-seat; **data leaves your perimeter**; not OSS; not dev-native |
| **Secret-scanning + AI hook** | [GitGuardian `ggshield`](https://www.helpnetsecurity.com/2026/04/15/product-showcase-gitguardian-ggshield-ai-hook/) | Hooks into Cursor/Claude Code/Copilot, blocks pre-prompt/pre-exec | **Secrets only (no PII)**; commercial cloud detection engine |
| **OSS LLM gateway** | [Trylon Gateway](https://github.com/trylonai/gateway) | Self-hosted FastAPI gateway, PII redaction | For apps **you build** and route through it — not for a dev using Cursor |
| **OSS agent firewall** | [Pipelock](https://www.helpnetsecurity.com/2026/05/04/pipelock-open-source-ai-agent-firewall/) | Sits between agents and internet; 48 credential patterns + prompt-injection | Credentials only; agent-centric, not developer-IDE-centric |
| **Browser DLP** | [PrivacyFirewall](https://github.com/privacyshield-ai/privacy-firewall) | In-browser interception | Browser only — misses CLI, git, IDE indexing, MCP |

**Nobody occupies the intersection** of: open-source **and** local-first
**and** secrets-*and*-PII **and** native to the developer's *whole* workflow
(git + IDE + live AI-API traffic + MCP). That intersection is the opening.

## 3. The true moat (honest version)

ContextDuty's moat is **not detection** — that's Presidio, and we say so out
loud. The moat is the **enforcement fabric** around it:

1. **Multi-surface coverage of one developer.** Secrets/PII leak through *four*
   doors: the IDE indexing files, a git commit, a live request to an AI API,
   and an MCP tool call. Every competitor covers *one* door. ContextDuty
   covers all four from a single `pip install` and one policy.
2. **Local-first + open-source.** No data leaves the machine; the detection
   logic, patterns, and logging are auditable. This is a hard requirement for
   the exact buyers who care most (regulated, security-conscious, the Samsung
   scenario) — and it's where every *cloud* DLP structurally cannot follow.
3. **Secrets *and* PII in one tool.** GitGuardian/Pipelock do secrets; Presidio
   does PII. ContextDuty fuses 60 deterministic regex detectors with Presidio's
   NLP so one policy covers both.
4. **Portable, opinionated policy.** Block/warn/redact per detector, allow/deny
   lists, layered policies, HIPAA/SOC2 baselines — a single JSON that travels
   with the repo and drives *every* surface. Presidio gives you operators, not
   a policy that gates a commit or a proxy.
5. **Deterministic masking.** The same secret always maps to the same token, so
   redaction is stable across diffs, logs, and audit trails — enabling review
   without re-exposure.

**What the moat is NOT:** novel detection technology, and not a deep technical
barrier. It is **integration breadth + local-first + OSS + opinionation + UX.**
That is a legitimate, defensible moat for an open-source developer tool (it's
how `ripgrep`, `pre-commit`, and `ggshield` won), but it is a
distribution/positioning moat, not a patent. Treat it accordingly: win on
adoption and ergonomics, not on a detection-accuracy arms race we'd lose.

## 4. One-line positioning

> **ContextDuty is the open-source, local-first prompt firewall: it wires
> Microsoft Presidio's detection into every place a developer leaks — git, the
> IDE, live AI-API traffic, and MCP — and enforces one portable policy across
> all of them. No cloud. No per-seat SaaS. Nothing leaves your machine.**

Presidio is the brain. ContextDuty is the firewall.

## 5. Rough opportunity sizing (assumptions explicit)

These are order-of-magnitude estimates to sanity-check the bet, not a forecast.

- Developers worldwide: ~**30M**. Using AI coding assistants (2026): ~**70%** → **~21M**.
- Of those, the leak problem is near-universal (34.8% of inputs sensitive), so
  the *addressable* population ≈ the AI-assistant user base.
- OSS dev-security tools convert a small slice to active users. At a
  conservative **1–3%** reach of AI-assistant users → **210k–630k** potential
  installs; security-conscious teams are the dense core.
- **Monetization (open-core):** the CLI/hooks/proxy stay free and OSS (drives
  adoption); revenue comes from a team/enterprise tier — centralized policy
  management, audit dashboard + retention, SSO/RBAC, fleet rollout.
  - If even **0.5%** of, say, 300k active users sit in teams paying **$15/seat/mo**
    at an avg team of 10 → 1,500 teams × 10 × $15 × 12 ≈ **$2.7M ARR** as a
    rough upper-bound sketch. The point isn't the number; it's that an
    OSS-led, enterprise-upsell motion is **plausible** at modest adoption.

**Conclusion:** demand is proven and accelerating; the gap (OSS + local +
multi-surface + secrets&PII) is genuinely unoccupied; the moat is real but
shallow. The right strategy is **adoption-first, Presidio-credited, workflow-
differentiated** — exactly the "demo → PyPI → enterprise tier" path already
chosen. Do not market detection superiority; market *coverage, locality, and
zero-friction enforcement.*

## 6. Risks

- **Thin moat:** GitGuardian could add PII; a Presidio-based startup could add
  hooks. Mitigation: move fast on breadth + UX + community, become the default.
- **Vendor pull:** ChatGPT/Copilot Enterprise add native DLP. Mitigation: we
  cover *cross-tool* + *local-first* + *OSS auditability* they can't match per-vendor.
- **Maintenance of the proxy/cert story** (mitmproxy) is the highest-friction
  surface; keep it optional and dead-simple.
