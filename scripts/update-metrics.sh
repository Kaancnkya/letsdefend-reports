#!/usr/bin/env bash
# Regenerate the metrics line and the case index in README.md from the cases/ directory.
# Usage: scripts/update-metrics.sh [alerts_triaged]
#   alerts_triaged is the running count from the LetsDefend dashboard (optional; kept if omitted).
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
README="$REPO/README.md"

reports=0
rows=""
while IFS= read -r d; do
  [[ -f "$d/report.md" ]] || continue
  base="$(basename "$d")"
  date="${base%%_*}"
  rest="${base#*_}"
  id="${rest%%-*}"
  title="${rest#*-}"
  title="${title//-/ }"
  vline="$(grep -m1 '\*\*Verdict:\*\*' "$d/report.md" | sed -E 's/.*\*\*Verdict:\*\*[[:space:]]*//' || true)"
  if [[ -z "$vline" || "$vline" == *"["* ]]; then   # placeholder still in place → not filled in yet
    verdict="—"
    title="$title (draft)"
  else
    verdict="$(printf '%s' "$vline" | grep -oE 'True Positive|False Positive' | head -1 || true)"
    [[ -n "$verdict" ]] || verdict="—"
    reports=$((reports + 1))               # only finished reports count toward the metric
  fi
  rows+="| $date | [\`$id\`](./cases/$base/report.md) | $title | $verdict |"$'\n'
done < <(find "$REPO/cases" -mindepth 1 -maxdepth 1 -type d | sort -r)

[[ -n "$rows" ]] || rows="| — | — | no published cases yet | — |"$'\n'

alerts="$(grep -oE '\*\*[0-9]+\*\* alerts' "$README" | grep -oE '[0-9]+' || echo 0)"
[[ $# -ge 1 ]] && alerts="$1"

python3 - "$README" "$alerts" "$reports" "$rows" <<'PY'
import re, sys
path, alerts, reports, rows = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
text = open(path).read()
metrics = f"**{alerts}** alerts triaged · **{reports}** incident reports published"
text = re.sub(r"(?s)(<!-- metrics:start -->).*?(<!-- metrics:end -->)",
              lambda m: f"{m.group(1)}\n{metrics}\n{m.group(2)}", text)
table = "| Date | Case | Topic | Verdict |\n|---|---|---|---|\n" + rows
text = re.sub(r"(?s)(<!-- cases:start -->).*?(<!-- cases:end -->)",
              lambda m: f"{m.group(1)}\n{table}{m.group(2)}", text)
open(path, "w").write(text)
print(metrics)
PY
