#!/usr/bin/env python3
"""ContextDuty launch demo — shows the enforcement surfaces a paste-box (Presidio
demo / HF Space) structurally cannot: git hook, live AI-traffic proxy, IDE
indexing block, MCP. Real masks are computed by ContextDuty, not faked.

Recorded headless via:  asciinema rec --command "python demo/firewall_demo.py"
"""

from __future__ import annotations

import sys
import time

from contextduty.detectors import stable_mask

# ── ANSI ────────────────────────────────────────────────────────────────────
R = "\033[0m"
B = "\033[1m"
DIM = "\033[2m"
CYAN = "\033[36m"
GREEN = "\033[32m"
RED = "\033[31m"
YEL = "\033[33m"
MAG = "\033[35m"
GREY = "\033[90m"


def w(s: str = "", d: float = 0.0) -> None:
    sys.stdout.write(s + "\n")
    sys.stdout.flush()
    if d:
        time.sleep(d)


def typ(s: str, d: float = 0.012) -> None:
    for ch in s:
        sys.stdout.write(ch)
        sys.stdout.flush()
        time.sleep(d)
    sys.stdout.write("\n")
    sys.stdout.flush()


def prompt(cmd: str, pause: float = 0.5) -> None:
    sys.stdout.write(f"{GREEN}${R} ")
    sys.stdout.flush()
    typ(cmd, 0.018)
    time.sleep(pause)


def vs_presidio(text: str) -> None:
    w(f"  {GREY}Presidio / HF demo: {RED}✗ {GREY}{text}{R}", 0.7)


def header() -> None:
    w()
    w(f"{B}{CYAN}  ContextDuty — the local AI prompt firewall{R}", 0.3)
    w(f"{DIM}  Presidio DETECTS PII. ContextDuty ENFORCES it — everywhere you leak.{R}", 0.5)
    w()
    w(f"{DIM}  A paste-box shows detection. Here's what it can't show:{R}", 1.0)
    w()


def scene_hook() -> None:
    w(f"{B}{MAG}━━ 1. Git pre-commit hook ━━{R}", 0.4)
    prompt('git commit -m "add deploy config"')
    w()
    w(f"{RED}[ContextDuty] BLOCKED: config.py{R}", 0.2)
    w(f"  aws_key: 1 finding(s)", 0.2)
    w(f"  openai_key: 1 finding(s)", 0.4)
    w(f"{RED}  ✗ commit rejected — secret never enters git history{R}", 0.5)
    vs_presidio("no git integration")
    w()


def scene_proxy() -> None:
    w(f"{B}{MAG}━━ 2. Live AI-traffic proxy  (the part nothing else does) ━━{R}", 0.4)
    prompt("contextduty proxy start", 0.3)
    w(f"{DIM}  Listening 127.0.0.1:8080 · intercepting 21 AI API hosts{R}", 0.6)
    w()
    w(f"{DIM}  …your IDE sends a prompt to api.openai.com:{R}", 0.5)
    aws_mask = stable_mask("aws_key", "AKIA1234567890ABCDEF")
    dsn_mask = stable_mask("postgres_dsn", "postgres://admin:p4ss@prod-db:5432/users")
    w(f'  {GREY}"debug my deploy — key=AKIA1234567890ABCDEF '
      f'db=postgres://admin:p4ss@prod-db:5432/users"{R}', 0.8)
    w()
    w(f"{YEL}  [ContextDuty] ✂  api.openai.com  intercepted{R}", 0.3)
    w(f"     aws_key       AKIA…ABCDEF             {GREEN}→ {aws_mask}{R}", 0.3)
    w(f"     postgres_dsn  postgres://admin:…      {GREEN}→ {dsn_mask}{R}", 0.5)
    w(f"{GREEN}{B}  → OpenAI received the masked version. "
      f"Your key never left the laptop.{R}", 0.6)
    vs_presidio("can't touch your traffic — it's a library, not a wire")
    w()


def scene_ide() -> None:
    w(f"{B}{MAG}━━ 3. IDE indexing block ━━{R}", 0.4)
    prompt("contextduty protect")
    w(f"{GREEN}  ✓ wrote 6 ignore files:{R}", 0.3)
    for f in (".cursorignore", ".copilotignore", ".codeiumignore",
              ".tabnine_ignore", ".amazonq/ignore", ".cody/ignore"):
        w(f"     {GREEN}✓{R} {f}", 0.08)
    w(f"{DIM}  → 6 AI tools blocked from ever indexing your secret files{R}", 0.5)
    vs_presidio("no IDE integration")
    w()


def scene_mcp() -> None:
    w(f"{B}{MAG}━━ 4. MCP server ━━{R}", 0.4)
    prompt("contextduty-mcp", 0.2)
    w(f"  agent reads customers.json → "
      f'{GREY}{{"ssn": "123-45-6789"}}{R}', 0.3)
    ssn_mask = stable_mask("ssn", "123-45-6789")
    w(f"  ContextDuty rewrites →        {GREEN}{{\"ssn\": \"{ssn_mask}\"}}{R}", 0.4)
    w(f"{DIM}  → real values never enter the agent's context window{R}", 0.5)
    vs_presidio("no MCP / agent-loop integration")
    w()


def outro() -> None:
    w(f"{B}{CYAN}  Presidio is the brain.  ContextDuty is the firewall.{R}", 0.4)
    w(f"{DIM}  60 detectors + Presidio NLP · git · IDE · proxy · MCP · 100% local · MIT{R}", 0.4)
    w()
    w(f"{B}{GREEN}  $ pip install contextduty{R}", 0.3)
    w(f"{DIM}  github.com/SHUBHAGYTA24/contextduty{R}", 1.2)
    w()


def main() -> None:
    header()
    scene_hook()
    scene_proxy()
    scene_ide()
    scene_mcp()
    outro()


if __name__ == "__main__":
    main()
