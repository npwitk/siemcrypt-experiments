#!/usr/bin/env bash
# Journal-version experiments (LAPH, authenticated EPII, ACL). Only what the final run
# (results/vm-m7i-2xlarge-final/) does not already cover; see docs/journal-experiments.md.
#   bash experiments/run_journal.sh                 full runs into results/
#   bash experiments/run_journal.sh --quick         dry run (minutes)
#   SKIP_AIT=1 bash experiments/run_journal.sh      synthetic experiments only
#   SIEMCRYPT_RESULTS=/path bash ...                write somewhere else
# FP_GAMMA (default 1.7) is the fixed-padding gamma matched to LAPH's budget; e3_laph.py
# prints the matched value on the synthetic development stream.
set -euo pipefail
cd "$(dirname "$0")/.."
Q="${1:-}"
W="${WORKERS:-8}"
OUT="${SIEMCRYPT_RESULTS:-results}"
mkdir -p "$OUT"
python -c "import platform,sys; print(platform.platform(), sys.version)" > "$OUT/env_python_journal.txt"
git rev-parse HEAD > "$OUT/env_commit_journal.txt" 2>/dev/null || true
python -m pytest -q tests

python experiments/e5_acl.py --workers "$W"                       # Exp 5 table: deviations vs ACL
python experiments/e5_integrity.py --variant J --workers "$W" --bits 2048 $Q   # Exp 6: dual authentication
python experiments/e2_acl_scale.py $Q                             # Exp 2/5 figures: ACL scalability (2048-bit)
python experiments/e3_laph.py --workers "$W" $Q                   # Exp 3: NP / FP / LAPH
python experiments/e4_temporal.py --workers "$W" $Q               # Exp 4: NoHist / FixedDecay / NoContract / drift

if [ -z "${SKIP_AIT:-}" ]; then                                   # Exp 3/4 on real data
  python experiments/ait_eval.py --parts e1,e3 --tag journal --workers "$W" --heavy-workers "${HEAVY_WORKERS:-3}" \
    --systems S,A2,FixedDecay,LAPH,FP --rules B1-default --leak-systems S,FP,LAPH,SD \
    --fp-gamma "${FP_GAMMA:-1.7}" $Q
fi
echo "done: $OUT/*.md"
