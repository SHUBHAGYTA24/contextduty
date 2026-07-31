#!/usr/bin/env bash
# ContextDuty for Teams — live demo.
#
# Shows the whole team story end-to-end: a developer works normally, a fleet
# dashboard lights up, a --no-verify bypass is caught, and NO code/secrets ever
# leave the machine. Safe to run anywhere — uses a throwaway repo and a local
# collector, and cleans up on exit.
#
#   bash demo/team_demo.sh

set -uo pipefail

PORT=7097
WORK="$(mktemp -d)"
STORE="$WORK/fleet.jsonl"
COLL_PID=""

say()  { printf "\n\033[1;36m%s\033[0m\n" "$*"; }
step() { printf "\033[1;35m▶ %s\033[0m\n" "$*"; }
run()  { printf "\033[2m  $ %s\033[0m\n" "$*"; eval "$*"; }
pause(){ printf "\033[2m  (press Enter)\033[0m"; read -r _; }

cleanup() {
  [ -n "$COLL_PID" ] && kill "$COLL_PID" >/dev/null 2>&1
  rm -rf "$WORK"
}
trap cleanup EXIT

say "ContextDuty for Teams — live demo"
echo "  Everything runs locally. Nothing leaves this machine."

# 1. The dashboard the customer runs inside their own network.
step "1. Start the fleet dashboard (self-hosted, on localhost)"
run "python -m contextduty.cli team serve --port $PORT --store '$STORE' --no-open >/dev/null 2>&1 &"
COLL_PID=$!
sleep 2
echo "  Dashboard: http://127.0.0.1:$PORT   (open it in a browser)"
pause

# 2. A developer's repo, enrolled + protected.
step "2. A developer enrolls their repo and installs the guard"
cd "$WORK"
run "git init -q && git config user.email demo@dev.co && git config user.name demo"
run "python -m contextduty.cli team enroll --url http://127.0.0.1:$PORT >/dev/null"
run "python -m contextduty.cli install-hooks >/dev/null 2>&1"
echo "  → this endpoint now reports (metadata only) to the dashboard."
pause

# 3. Normal work — the guard runs, the endpoint is healthy.
step "3. The developer makes a normal commit (the guard runs)"
run "echo 'print(1)' > app.py && git add app.py .contextduty.json"
run "git commit -q -m 'add app'"
echo "  → refresh the dashboard: 1 endpoint, enforcing. No bypass."
pause

# 4. The bypass — sneaking a commit past the guard.
step "4. The developer BYPASSES the guard:  git commit --no-verify"
run "echo 'oops' > b.txt && git add b.txt"
run "git commit -q --no-verify -m 'sneaky'"
sleep 1
echo "  → refresh the dashboard: a RED tamper event appears —"
echo "     'bypass — git commit --no-verify'.  Caught in ~1 second."
pause

# 5. The punchline — we caught it without seeing anything.
step "5. What actually left the machine?  (open the store)"
echo "  Every line the endpoint sent:"
printf "\033[2m"
cat "$STORE" | sed 's/^/    /'
printf "\033[0m"
say "Notice: hostnames, counts, an event name — NO code, NO secrets, NO prompts."
echo "  You saw the bypass. You never saw a line of their code."
echo
echo "  That's ContextDuty for Teams: fleet visibility, self-hosted, metadata-only."
