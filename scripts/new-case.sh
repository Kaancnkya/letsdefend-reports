#!/usr/bin/env bash
# Scaffold a new case folder from the templates.
# Usage: scripts/new-case.sh SOC176 "phishing url"
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ $# -lt 2 ]]; then
  echo "usage: $(basename "$0") <CASE-ID> <short title>" >&2
  echo "example: $(basename "$0") SOC176 \"phishing url\"" >&2
  exit 1
fi

CASE_ID="$1"; shift
TITLE="$*"

slug="$(printf '%s' "$TITLE" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9]+/-/g; s/^-+|-+$//g')"
dir="$REPO/cases/$(date +%F)_${CASE_ID}-${slug}"

if [[ -e "$dir" ]]; then
  echo "already exists: $dir" >&2
  exit 1
fi

mkdir -p "$dir/screenshots"
sed "s/\[CASE-ID\]/$CASE_ID/g; s/\[Short title\]/$TITLE/" "$REPO/templates/incident-report.md" > "$dir/report.md"
sed "s/\[CASE-ID\]/$CASE_ID/g" "$REPO/templates/notes.md" > "$dir/notes.md"
cp "$REPO/templates/iocs.csv" "$dir/iocs.csv"
: > "$dir/screenshots/.gitkeep"

echo "$dir"
