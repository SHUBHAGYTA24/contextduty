# ContextDuty Enterprise Deployment Guide

This guide covers deploying ContextDuty at scale — from a team of 10 to an
organization of 10,000+ engineers. It is written for security engineers and
platform teams responsible for AI tooling governance.

---

## Prerequisites

- Python 3.10+ on all developer machines
- Existing configuration management (dotfiles, Chef, Ansible, Puppet, or MDM)
- A central policy repository accessible to all engineers

---

## Deployment Patterns

### Pattern 1 — Dotfiles repo (recommended for most orgs)

The simplest enterprise deployment. Engineers manage their machine setup via a
shared dotfiles repo (e.g. `github.com/your-org/dotfiles`).

**Step 1 — Add ContextDuty to your dotfiles bootstrap script:**

```bash
# scripts/bootstrap.sh
pip install contextduty

# Pull the org policy to a shared location all projects can extend
mkdir -p ~/.contextduty
curl -sSL https://raw.githubusercontent.com/your-org/policies/main/contextduty/org-baseline.json \
  -o ~/.contextduty/org-baseline.json
```

**Step 2 — Add the Cursor/Claude MCP config to dotfiles:**

```bash
# For Cursor
mkdir -p ~/.cursor
cat >> ~/.cursor/mcp.json << 'EOF'
{
  "mcpServers": {
    "contextduty": {
      "command": "contextduty-mcp"
    }
  }
}
EOF
```

**Step 3 — Engineers extend the org baseline in each project:**

```json
{
  "extends": "~/.contextduty/org-baseline.json",
  "mode": "block",
  "detectors": []
}
```

Or, for URL-based distribution (no local file needed):

```json
{
  "extends": "https://policies.your-org.com/contextduty/org-baseline.json",
  "mode": "block",
  "detectors": []
}
```

---

### Pattern 2 — Managed dev containers

For organizations using devcontainers (VS Code Remote, GitHub Codespaces,
Docker-based development environments).

**Add to your base devcontainer image's Dockerfile:**

```dockerfile
# Install ContextDuty globally in the dev image
RUN pip install contextduty==0.1.0

# Pre-install org policy
COPY policies/contextduty/org-baseline.json /etc/contextduty/org-baseline.json

# Set environment variable pointing to org policy
ENV CONTEXTDUTY_ORG_POLICY=/etc/contextduty/org-baseline.json
```

**Set the default project policy in your `.devcontainer/devcontainer.json`:**

```json
{
  "postCreateCommand": "contextduty init && echo '{\"extends\": \"/etc/contextduty/org-baseline.json\", \"mode\": \"block\"}' > .contextduty.json"
}
```

---

### Pattern 3 — Chef / Ansible / Puppet

For organizations managing developer machines via configuration management tools.

**Ansible example:**

```yaml
# roles/developer-setup/tasks/contextduty.yml
- name: Install ContextDuty
  pip:
    name: contextduty==0.1.0
    state: present

- name: Create ContextDuty config directory
  file:
    path: "{{ ansible_env.HOME }}/.contextduty"
    state: directory
    mode: "0755"

- name: Distribute org policy
  copy:
    src: files/contextduty/org-baseline.json
    dest: "{{ ansible_env.HOME }}/.contextduty/org-baseline.json"
    mode: "0644"

- name: Configure Cursor MCP
  template:
    src: templates/cursor-mcp.json.j2
    dest: "{{ ansible_env.HOME }}/.cursor/mcp.json"
    mode: "0644"
```

---

### Pattern 4 — URL-based centralized policy (zero local config)

The highest-leverage enterprise pattern. Your security team hosts one canonical
policy URL. Engineers' `.contextduty.json` files contain only one line:

**Host your org baseline (example using GitHub Pages or any static hosting):**

```
https://security.your-org.com/contextduty/baseline-2026.json
```

**Each project's `.contextduty.json`:**

```json
{
  "extends": "https://security.your-org.com/contextduty/baseline-2026.json",
  "mode": "block"
}
```

**Benefits:**
- Security team updates the policy at the URL — no changes required on developer machines
- Policy updates take effect on the next scan without any engineer action
- Different teams can extend the same base with team-specific detectors

---

## Central Audit Log Collection

ContextDuty's `--audit-log` flag writes structured JSONL. For enterprise
collection, ship these logs to your SIEM or central logging infrastructure.

**Per-developer (appends to a shared NFS or S3-mounted path):**

```bash
contextduty scan src/config.py \
  --audit-log /mnt/security-logs/contextduty/$(hostname).jsonl
```

**In CI (per-pipeline, shipped to S3):**

```yaml
- name: Scan and audit
  run: |
    contextduty scan src/ \
      --audit-log /tmp/contextduty-audit.jsonl
    aws s3 cp /tmp/contextduty-audit.jsonl \
      s3://your-security-logs/contextduty/${GITHUB_RUN_ID}.jsonl
```

**Generate a summary report:**

```bash
contextduty report --audit-log /var/log/contextduty/audit.jsonl --out report.json
```

Report fields include:
- `total_scans`, `total_findings`, `total_blocked`, `block_rate_pct`
- `detector_totals` — which detectors fired most
- `blocked_by_totals` — which detectors caused blocks
- `scans_by_user` — per-engineer scan activity

---

## CI Integration

**Fail pipeline if any sensitive values are found in a specific file:**

```yaml
# .github/workflows/contextduty.yml
name: ContextDuty scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install contextduty
      - run: contextduty scan src/config.py --policy .contextduty.json
      - run: contextduty scan .env.example --policy .contextduty.json
```

**With audit log shipped to S3:**

```yaml
      - run: |
          contextduty scan src/ \
            --audit-log /tmp/audit.jsonl
          aws s3 cp /tmp/audit.jsonl \
            s3://security-logs/contextduty/${{ github.run_id }}.jsonl
```

---

## Policy Governance

### Org baseline structure

```
your-org/policies/
  contextduty/
    org-baseline.json       ← extended by all teams
    soc2-strict.json        ← extends org-baseline, used by data teams
    hipaa.json              ← extends soc2-strict, used by health teams
```

### Policy update process

1. Security team opens a PR to update `org-baseline.json`
2. CI validates the policy: `contextduty policy validate --policy org-baseline.json --strict`
3. PR reviewed by security lead + one staff engineer from an affected team
4. Merge — policy takes effect immediately for URL-based distribution,
   or on next `dotfiles pull` for file-based distribution

---

## Recommended Settings by Team Type

| Team | Mode | Key detector_modes | Notes |
|---|---|---|---|
| All teams (baseline) | `redact` | `api_key: block`, `aws_key: block` | Credentials always block |
| Health / HIPAA | `block` | All detectors: `block` | Use HIPAA policy pack |
| Finance / PCI | `block` | All detectors: `block` | Add custom card number detector |
| Data pipelines | `warn` | `api_key: block` | High false-positive rate for emails |
| Developer tooling | `redact` | `api_key: block` | Allow system emails via allow_patterns |

---

## Compliance Evidence

For SOC 2 / HIPAA audits, collect:

1. **Policy file** — the `.contextduty.json` in use, version-controlled
2. **Audit log samples** — JSONL entries showing scan coverage
3. **CI run logs** — evidence that scanning runs on every PR
4. **`contextduty report` output** — summary statistics for the audit period

---

## Current Limitations

Be transparent with your security team about these:

- **No directory scanning yet** — scan individual files, not `src/` directories. Roadmap.
- **No GUI dashboard** — audit reporting is CLI + JSON. SIEM integration is the recommended path.
- **Phone detection is North American only** — international formats not yet supported.
- **Free-text PII (names, locations)** — regex-based detection cannot catch these. Complement with Presidio if required.
- **Typed input is not intercepted** — ContextDuty intercepts file context injected by MCP clients, not text typed directly into chat.
- **Single maintainer** — see SUPPORT.md for current support model.

---

## Getting Help

- GitHub Issues: https://github.com/SHUBHAGYTA24/contextduty/issues
- Security issues: see SECURITY.md
- Enterprise questions: open a GitHub Discussion
