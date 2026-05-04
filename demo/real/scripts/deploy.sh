#!/usr/bin/env bash
# deploy.sh — production deployment script
# TODO: move secrets to Vault before Q3 (created 2024-11-01, still TODO)
# NOTE: All values are intentionally fake — used only for ContextDuty demos.

set -euo pipefail

# AWS credentials — should be in env, ended up hardcoded after CI broke
# (canonical AWS documentation example keys — not real)
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Notify Slack on deploy start (demo — caught by env_secret; not a real token)
SLACK_TOKEN="EXAMPLEcontextdutyDEMOslacktokenXXXXXXXXXXXXX"
curl -s -X POST https://slack.com/api/chat.postMessage \
  -H "Authorization: Bearer $SLACK_TOKEN" \
  -d "channel=#deploys&text=Deploy started by $(git config user.email)"

# Tag the release in GitHub (demo pattern — not a real token)
GITHUB_TOKEN="ghp_EXAMPLEcontextdutyDEMOXXXXXXXXXXXX123"
curl -s -X POST https://api.github.com/repos/myapp/backend/releases \
  -H "Authorization: token $GITHUB_TOKEN" \
  -d '{"tag_name":"'"$1"'","name":"Release '"$1"'"}'

# Push Docker image to ECR
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin 123456789.dkr.ecr.us-east-1.amazonaws.com

echo "Deploy of $1 complete. Notify: ops@myapp.com / +1-415-555-0182"
