# Full synthetic run, AWS m7i.2xlarge, 2026-10-11 (run 2)

Commit `d263ca7` (see `env_commit.txt`). Intel Xeon Platinum 8488C, 8 vCPU, Ubuntu 24.04, Python 3.12.

E1–E5 on synthetic data and the E2 microbenchmarks, with the current system names (S = no decoys, SD = decoys).
Compared with run 1, E1 adds the threshold-free AUC and recall@FP2.

The AIT-LDSv2 part of this run stopped during calibration with an overflow in the Phase 5 risk sigmoid, which was fixed afterwards. `full.log` ends with that traceback. The AIT results are in a separate folder.
