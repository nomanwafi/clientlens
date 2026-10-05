#!/usr/bin/env bash
#
# monthly-scan.sh — run ClientLens against a list of domains and diff
# against the previous run.
#
# Usage:
#   ./monthly-scan.sh clients.txt
#
# clients.txt is one domain per line, `#` for comments.
#
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <clients.txt>" >&2
  exit 2
fi

LIST="$1"
[[ -f "$LIST" ]] || { echo "no such file: $LIST" >&2; exit 2; }

STAMP=$(date +%Y-%m-%d)
OUT="reports/$STAMP"
mkdir -p "$OUT"

# Per-client database keeps history tidy.
export CLIENTLENS_DB="${CLIENTLENS_DB:-$HOME/.clientlens/monthly.db}"

echo "ClientLens monthly sweep"
echo "  list    : $LIST"
echo "  output  : $OUT"
echo "  database: $CLIENTLENS_DB"
echo

while read -r domain; do
  # skip blanks and comments
  [[ -z "${domain// }" ]] && continue
  [[ "$domain" == \#* ]] && continue

  echo "=== $domain ==="
  if uv run clientlens scan "$domain" --i-am-authorized --no-crtsh \
       --html "$OUT/$domain.html" \
       -o    "$OUT/$domain.json"; then
    echo "  ok — no critical/high findings"
  else
    code=$?
    if [[ $code -eq 3 ]]; then
      echo "  ⚠ $domain has critical or high findings — see $OUT/$domain.html"
    else
      echo "  ✗ scan failed (exit $code) — skipping"
    fi
  fi
  echo
done < "$LIST"

echo "Done. Reports in $OUT/"
echo "Open the dashboard for a cross-scan view:"
echo "  uv run clientlens dashboard"
