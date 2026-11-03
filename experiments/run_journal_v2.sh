#!/usr/bin/env bash
# Journal v2 experiments (AQRS with D29 partitioned cohorts and cohort-aligned padding, upgraded ACL,
# versioned profiles, lineage-scoped investigation). J2 = ACL + D29 (experiments/common.py).
#   bash experiments/run_journal_v2.sh                 full runs into results/
#   bash experiments/run_journal_v2.sh --quick         dry run
#   SKIP_AIT=1 bash experiments/run_journal_v2.sh      synthetic experiments only
#   SKIP_SCALE=1 ...                                   skip the 10^7 Exp 2 point (needs ~16 GB)
#   SIEMCRYPT_RESULTS=/path bash ...                   write somewhere else
# Every step logs to $OUT/logs/<step>.log; a failed step is reported and the run continues.
set -uo pipefail
cd "$(dirname "$0")/.."
Q="${1:-}"
W="${WORKERS:-8}"
OUT="${SIEMCRYPT_RESULTS:-results}"
export SIEMCRYPT_RESULTS="$OUT"
mkdir -p "$OUT/logs"
python -c "import platform,sys,os; print(platform.platform(), sys.version, os.cpu_count(), 'cpus')" > "$OUT/env_python_journal_v2.txt"
git rev-parse HEAD > "$OUT/env_commit_journal_v2.txt" 2>/dev/null || true
FAILED=()
step() {  # step <name> <command...>
  local name="$1"; shift
  echo "== $name: $* ($(date '+%F %T'))"
  local t0=$SECONDS
  if "$@" > "$OUT/logs/$name.log" 2>&1; then
    echo "   ok in $((SECONDS - t0)) s"
  else
    echo "   FAILED after $((SECONDS - t0)) s (see $OUT/logs/$name.log)"; FAILED+=("$name")
  fi
}

step tests python -m pytest -q tests
NS="10000,100000,1000000,10000000"
[ -n "${SKIP_SCALE:-}" ] && NS="10000,100000,1000000"
step e2_scale python experiments/e2_acl_scale.py --ns "$NS" $Q                  # Exp 2: q/N, N to 10^7, j_q, S-FullHE
step e2_scoping python experiments/e2_scoping.py $Q                             # Exp 2: HE ops scoped by EPII
E3SYS=Direct,Fixed-3,Fixed-5,AQRS,Dynamic-Cover,AQRS-D28w,AQRS-D28e+P,Fixed-5-G,Fixed-5-G+CPt,Fixed-5-G+CP,AQRS-G3+CPt
# Exp 3 privacy does not depend on the key size: 5 seeds at 512 bits; 2048-bit timings on 2 seeds
step e3_aqrs python experiments/e3_aqrs.py --workers "$W" --bits 512 --systems "$E3SYS" $( [ -n "$Q" ] && echo --quick )
step e3_aqrs_2048 python experiments/e3_aqrs.py --workers "$W" --bits 2048 --seeds 2 --tag 2048 \
  --systems "$( [ -n "$Q" ] && echo Direct,Fixed-5-G+CPt || echo "$E3SYS" )" $( [ -n "$Q" ] && echo --quick )
step e3_padding python experiments/e3_d29_padding.py --workers "$W" $( [ -n "$Q" ] && echo --seeds 2 )  # Exp 3: volume attacks, F1
step e4_temporal python experiments/e4_temporal.py --workers "$W" $Q            # Exp 4: lns sweep, drift, state
step e4_v2 python experiments/e4_v2.py --workers "$W" $Q                        # Exp 4: No-Graph, Fixed-Window, gap, pid
step e5_acl python experiments/e5_acl.py --workers "$W" --variant J2 $( [ -n "$Q" ] && echo --trials 2 )  # Exp 5
step e5_integrity python experiments/e5_integrity.py --variant J2 --workers "$W" --bits 2048 $Q        # Exp 6 dual auth
step e6_v2 python experiments/e6_v2.py --workers 4 --bits 2048 $Q               # Exp 6: span, Full-History, C_Inv

if [ -z "${SKIP_AIT:-}" ]; then                                                 # Exp 3/4 on real data
  step ait python experiments/ait_eval.py --parts e1,e3 --tag journal_v2 --workers "$W" \
    --heavy-workers "${HEAVY_WORKERS:-3}" --systems S,A2,FixedDecay,LAPH-E,J2 --rules B1-default \
    --leak-systems S,LAPH-E,J2 $Q
fi
if [ ${#FAILED[@]} -gt 0 ]; then echo "failed steps: ${FAILED[*]}"; exit 1; fi
echo "done: $OUT/*.md"
