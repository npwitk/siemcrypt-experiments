#!/usr/bin/env bash
# Journal v2 follow-up (D30, 2026-11-05): padding-neutral detection (J2R = J2 + EE graph features over
# real records) and the grouping-size trade-off (J2R3 = k 3) on AIT-LDSv2, plus the synthetic design study.
# S, J2 and the rules are unchanged since results/vm-m7i-2xlarge-journal-v2/ and are not rerun.
#   bash experiments/run_journal_v2_design.sh            full run (about 6-8 h on m7i.2xlarge)
#   bash experiments/run_journal_v2_design.sh --quick    dry run
set -uo pipefail
cd "$(dirname "$0")/.."
Q="${1:-}"
W="${WORKERS:-8}"
OUT="${SIEMCRYPT_RESULTS:-results}"
export SIEMCRYPT_RESULTS="$OUT"
mkdir -p "$OUT/logs"
git rev-parse HEAD > "$OUT/env_commit_journal_v2_design.txt" 2>/dev/null || true
FAILED=()
step() {
  local name="$1"; shift
  echo "== $name: $* ($(date '+%F %T'))"
  local t0=$SECONDS
  if "$@" > "$OUT/logs/$name.log" 2>&1; then echo "   ok in $((SECONDS - t0)) s"
  else echo "   FAILED after $((SECONDS - t0)) s (see $OUT/logs/$name.log)"; FAILED+=("$name"); fi
}
step tests python -m pytest -q tests
step e3_design python experiments/e3_d29_design.py --workers "$W" $Q
step ait python experiments/ait_eval.py --parts e1,e3 --tag journal_v2_design --workers "$W" \
  --heavy-workers "${HEAVY_WORKERS:-3}" --systems J2R,J2R3 --rules "" --leak-systems J2R3 $Q
if [ ${#FAILED[@]} -gt 0 ]; then echo "failed steps: ${FAILED[*]}"; exit 1; fi
echo "done: $OUT/*.md"
