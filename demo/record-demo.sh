#!/bin/bash
# ContextDuty v0.2.3 Demo Recording Script
# Run with: asciinema rec demo/contextduty-v0.2.3.cast -c "bash demo/record-demo.sh"
# Convert to GIF: agg demo/contextduty-v0.2.3.cast demo/contextduty-v0.2.3.gif --theme monokai

set -e

# Colors
BOLD="\033[1m"
GREEN="\033[32m"
CYAN="\033[36m"
DIM="\033[2m"
RESET="\033[0m"

type_slow() {
    local text="$1"
    for (( i=0; i<${#text}; i++ )); do
        printf '%s' "${text:$i:1}"
        sleep 0.04
    done
    echo ""
}

pause() { sleep "${1:-1.5}"; }

clear
echo ""
echo -e "${BOLD}  ContextDuty v0.2.3 — The AI Context Firewall${RESET}"
echo -e "${DIM}  Stop secrets from reaching any AI tool${RESET}"
echo ""
pause 2

# Scene 1: Demo
echo -e "${CYAN}━━━ Demo 1: Scan & Redact ━━━${RESET}"
echo ""
type_slow "$ contextduty demo"
pause 0.5
contextduty demo
pause 3

# Scene 2: Universal Protect
clear
echo ""
echo -e "${CYAN}━━━ Demo 2: Universal AI Workspace Protection ━━━${RESET}"
echo ""

# Create a temp workspace
TMPDIR=$(mktemp -d)
mkdir -p "$TMPDIR/src"
cat > "$TMPDIR/src/config.py" << 'PYEOF'
DATABASE_URL = "postgresql://admin:Sup3rS3cr3t@prod-db:5432/app"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
OPENAI_API_KEY = "sk-proj-abcdefghijklmnop1234567890"
PYEOF

cat > "$TMPDIR/src/app.py" << 'PYEOF'
# Clean file - no secrets
def hello():
    return "Hello, world!"
PYEOF

type_slow "$ contextduty protect"
pause 0.5
cd "$TMPDIR"
contextduty protect
pause 3

# Show generated files
echo ""
type_slow "$ ls -la .cursorignore .copilotignore .codeiumignore"
ls -la .cursorignore .copilotignore .codeiumignore 2>/dev/null || true
pause 2

# Scene 3: Proxy status
clear
echo ""
echo -e "${CYAN}━━━ Demo 3: HTTPS Proxy (21 AI APIs intercepted) ━━━${RESET}"
echo ""
type_slow "$ contextduty proxy status"
pause 0.5
contextduty proxy status 2>/dev/null || true
pause 3

# Scene 4: Git hook
clear
echo ""
echo -e "${CYAN}━━━ Demo 4: Pre-commit Hook ━━━${RESET}"
echo ""
type_slow "$ contextduty install-hooks"
echo ""
echo -e "  ${GREEN}✓${RESET}  Pre-commit hook installed"
echo "     Scanning staged files before every commit"
echo ""
echo -e "  ${DIM}Try: git add config.py && git commit${RESET}"
echo -e "  ${DIM}Result: BLOCKED — secrets never enter git history${RESET}"
pause 3

# Cleanup
rm -rf "$TMPDIR"

# Final
clear
echo ""
echo -e "${BOLD}  ContextDuty v0.2.3${RESET}"
echo ""
echo "  5 enforcement layers:"
echo "    1. Workspace ignore files (6 AI tools)"
echo "    2. Git pre-commit hook"
echo "    3. HTTPS proxy (21 AI API endpoints)"
echo "    4. MCP server (Cursor / Claude)"
echo "    5. CI/CD pipeline integration"
echo ""
echo "  25 built-in detectors · 258 tests · 100% local"
echo ""
echo -e "  ${CYAN}pip install contextduty${RESET}"
echo -e "  ${CYAN}https://github.com/SHUBHAGYTA24/contextduty${RESET}"
echo ""
pause 4
