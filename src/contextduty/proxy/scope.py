"""AI API scope — single source of truth for which hosts and paths to intercept.

Design principle: surgical interception. Only AI API endpoints are inspected.
Everything else tunnels transparently. Users must never worry that ContextDuty
reads their banking, email, or social media traffic.

To add a new AI tool:
    1. Add its API host to AI_API_HOSTS
    2. If it uses non-standard paths, add to PROMPT_PATHS or mark as always-intercept
    That's it. The proxy, interceptor, and feed all read from this registry.
"""

from __future__ import annotations

# ─────────────────────────────────────────────────────────────────────────────
# AI API Host Registry
#
# Maps hostname → human-readable label.
# The proxy ONLY intercepts hosts in this registry.
# ─────────────────────────────────────────────────────────────────────────────

AI_API_HOSTS: dict[str, str] = {
    # ── Cursor IDE ────────────────────────────────────────────────────────────
    "api2.cursor.sh": "Cursor",
    "cursor.sh": "Cursor",
    # ── Anthropic / Claude ────────────────────────────────────────────────────
    "api.anthropic.com": "Claude API",
    # ── OpenAI ────────────────────────────────────────────────────────────────
    "api.openai.com": "OpenAI",
    # ── GitHub Copilot ────────────────────────────────────────────────────────
    "copilot.github.com": "GitHub Copilot",
    "api.githubcopilot.com": "GitHub Copilot",
    "copilot-proxy.githubusercontent.com": "GitHub Copilot",
    # ── Google ────────────────────────────────────────────────────────────────
    "generativelanguage.googleapis.com": "Google Gemini",
    "aiplatform.googleapis.com": "Google Vertex AI",
    # ── Azure ─────────────────────────────────────────────────────────────────
    "openai.azure.com": "Azure OpenAI",
    # ── Codeium / Windsurf ────────────────────────────────────────────────────
    "server.codeium.com": "Codeium",
    # ── Amazon ────────────────────────────────────────────────────────────────
    "codewhisperer.us-east-1.amazonaws.com": "CodeWhisperer",
    # ── Sourcegraph ───────────────────────────────────────────────────────────
    "sourcegraph.com": "Sourcegraph Cody",
    # ── Tabnine ───────────────────────────────────────────────────────────────
    "api.tabnine.com": "Tabnine",
    # ── Perplexity ────────────────────────────────────────────────────────────
    "api.perplexity.ai": "Perplexity",
    # ── Mistral ───────────────────────────────────────────────────────────────
    "api.mistral.ai": "Mistral",
    # ── Groq ──────────────────────────────────────────────────────────────────
    "api.groq.com": "Groq",
    # ── Together AI ───────────────────────────────────────────────────────────
    "api.together.xyz": "Together AI",
    # ── Fireworks AI ──────────────────────────────────────────────────────────
    "api.fireworks.ai": "Fireworks AI",
    # ── Cohere ────────────────────────────────────────────────────────────────
    "api.cohere.ai": "Cohere",
    # ── DeepSeek ──────────────────────────────────────────────────────────────
    "api.deepseek.com": "DeepSeek",
}

# Frozen set for O(1) lookup in the hot path
AI_HOSTS: frozenset[str] = frozenset(AI_API_HOSTS.keys())

# ─────────────────────────────────────────────────────────────────────────────
# Prompt paths — paths that carry prompt/context content.
# Paths NOT in this set (e.g. /v1/embeddings, /v1/images) are skipped.
# ─────────────────────────────────────────────────────────────────────────────

PROMPT_PATHS: frozenset[str] = frozenset(
    {
        "/v1/chat/completions",
        "/v1/completions",
        "/v1/messages",
        "/v1/engines",
    }
)

# Hosts where ALL paths are prompt-carrying (no need to check path).
# These hosts only serve AI prompt endpoints.
_ALWAYS_INTERCEPT_PATTERNS: tuple[str, ...] = (
    "copilot",
    "githubcopilot",
    "cursor.sh",
    "generativelanguage.googleapis.com",
    "aiplatform.googleapis.com",
    "codeium.com",
    "tabnine.com",
    "deepseek.com",
    "mistral.ai",
    "groq.com",
    "together.xyz",
    "fireworks.ai",
    "cohere.ai",
    "perplexity.ai",
)

# ─────────────────────────────────────────────────────────────────────────────
# Never-intercept list — safety rail.
# Even if these somehow end up in the proxy path, NEVER read their content.
# ─────────────────────────────────────────────────────────────────────────────

NEVER_INTERCEPT: frozenset[str] = frozenset(
    {
        "github.com",
        "google.com",
        "accounts.google.com",
        "login.microsoftonline.com",
        "slack.com",
        "linkedin.com",
        "twitter.com",
        "facebook.com",
    }
)


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────


def is_prompt_request(host: str, path: str) -> bool:
    """Return True if this request carries AI prompt content and should be intercepted."""
    if host in NEVER_INTERCEPT:
        return False
    if host not in AI_HOSTS:
        return False
    # Some hosts only serve prompts — intercept all paths
    if any(pattern in host for pattern in _ALWAYS_INTERCEPT_PATTERNS):
        return True
    # For OpenAI/Anthropic/Azure — only intercept known prompt paths
    return any(path.startswith(p) for p in PROMPT_PATHS)


def get_host_label(host: str) -> str:
    """Return human-readable label for a host, or formatted hostname."""
    return AI_API_HOSTS.get(host, host.split(".")[0].title())
