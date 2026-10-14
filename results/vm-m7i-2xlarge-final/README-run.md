# Final run (m7i.2xlarge, ap-southeast-1)

- Part 1, 2026-10-13 04:18-06:02 UTC, commit 2c1e719: real-Wazuh replay (`wazuh_*`, `final_part1.log`).
  run_all stopped at the AIT fetch (Zenodo 503).
- Part 2, 2026-10-13 09:29-23:16 UTC, commit a890b07: `run_all.sh` in full (`final.log`, memory in `final_mem2.log`).
- 2026-10-14: `e_baselines.py` re-run alone (`baselines_*`, `tfhe_gate_bench.csv`, `baselines_rerun.log`) after adding
  the tfhe `seeder_unix` feature; in part 2 the TFHE benchmark panicked on Linux and B5 had no gate time.
- `wazuh_alerts_*.jsonl.gz`: raw Wazuh alerts, gzipped (228 MB uncompressed).
