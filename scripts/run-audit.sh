#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

set -a
[ -f ~/agenciar-acessos/agenciar.env ] && . ~/agenciar-acessos/agenciar.env
[ -f ~/agenciar-acessos/agenciar.local.env ] && . ~/agenciar-acessos/agenciar.local.env
set +a

echo "=== WP Security Audit Runner ==="
echo "Started: $(date)"

REPORT_PATH=$("$SCRIPT_DIR/wp-security-audit.sh")
echo "Audit complete: $REPORT_PATH"

echo "Generating HTML report and sending email..."
python3 -I "$SCRIPT_DIR/generate-and-send-report.py" "$REPORT_PATH"

cd "$REPO_DIR"
if [ -d .git ]; then
  TODAY=$(date +%Y-%m-%d)
  git add dashboard/data/
  if ! git diff --cached --quiet; then
    git commit -m "$(cat <<EOF
audit: ${TODAY} security report

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
    git push origin main 2>/dev/null || git push origin HEAD 2>/dev/null || echo "WARN: git push failed — push manually"
    echo "Dashboard data pushed to GitHub"
  else
    echo "No new data to push"
  fi
fi

echo ""
echo "=== Audit complete ==="
echo "Finished: $(date)"
