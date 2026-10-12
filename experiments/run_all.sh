#!/usr/bin/env bash
# Runs every experiment and writes results/. Use on the evaluation VM (m7i.2xlarge, 8 vCPU).
#   bash experiments/run_all.sh            full runs
#   bash experiments/run_all.sh --quick    dry run (minutes)
#   SKIP_AIT=1 bash experiments/run_all.sh synthetic experiments only
set -euo pipefail
cd "$(dirname "$0")/.."
Q="${1:-}"
W="${WORKERS:-8}"
mkdir -p results
lscpu > results/env_cpu.txt 2>/dev/null || sysctl -a 2>/dev/null | grep machdep.cpu > results/env_cpu.txt || true
python -c "import platform,sys; print(platform.platform(), sys.version)" > results/env_python.txt
git rev-parse HEAD > results/env_commit.txt 2>/dev/null || true
pytest -q tests

# ---- synthetic data
python experiments/e2_microbench.py --bits 2048 $Q          # first: E4 reads T_rand from it
python experiments/smoke.py --bits 2048 --workers "$W" | tee results/smoke_2048.txt
python experiments/e1_accuracy.py --workers "$W" $Q
python experiments/e3_leakage.py --workers "$W" $Q
python experiments/e2_scoping.py --workers "$W" $Q          # B3 full-HE vs SG-HEF
python experiments/e4_tradeoff.py --workers "$W" $Q
python experiments/e5_integrity.py --workers "$W" --bits 2048 $Q
python experiments/e_baselines.py $Q                    # B5 PriSIEM, B7 EVSEB, B8 MK-Tree (needs Rust for B5)

# ---- real data: AIT-LDSv2 (text logs only, ~1 GB, fetched once into ~/data/ait-ldsv2)
if [ -z "${SKIP_AIT:-}" ]; then
  python tools/ait_fetch.py
  python experiments/ait_eval.py --workers "$W" --heavy-workers "${HEAVY_WORKERS:-3}" $Q
fi

# ---- published baselines on their own datasets (B4: CSE-CIC-IDS2018, B6: Kyoto 2016)
if [ -z "${SKIP_EXT:-}" ]; then
  python tools/cicids2018_fetch.py
  python experiments/e_b4_wingarz.py $Q
  python tools/kyoto_fetch.py
  python experiments/e_b6_ogawa.py
fi
echo "done: results/*.md"
