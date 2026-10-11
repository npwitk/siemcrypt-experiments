# Running the experiments on AWS

All timing results in the paper come from one machine: AWS EC2 `m7i.2xlarge`
(8 vCPU, 32 GB), Ubuntu Server 24.04 LTS x86_64, region ap-southeast-1 (Singapore).

## 1. Launch
EC2 → Launch instance:
- AMI **Ubuntu Server 24.04 LTS (HVM), SSD Volume Type**, 64-bit (x86). Not Ubuntu Pro, not a Deep Learning AMI.
- Instance type **m7i.2xlarge** (on demand; burstable types distort timings).
- Key pair: create one, download the `.pem`, then run `chmod 400 key.pem`.
- Security group: SSH (22) from **My IP** only.
- Storage: 30 GB gp3. Use 200 GB later for Wazuh.

## 2. Set up (on the VM)
```bash
sudo apt update && sudo apt install -y python3-venv python3-dev build-essential libgmp-dev libmpfr-dev libmpc-dev tmux git
git clone <this repository> siemcrypt-experiments && cd siemcrypt-experiments
python3 -m venv .venv && source .venv/bin/activate
pip install -U pip && pip install -e ".[dev,experiments]"
pytest -q
```

## 3. Run (inside tmux, so that it survives a disconnect)
```bash
tmux new -s exp
source .venv/bin/activate
bash experiments/run_all.sh --quick 2>&1 | tee results/dryrun.log   # minutes
bash experiments/run_all.sh 2>&1 | tee results/full.log              # full run
```
Detach with `Ctrl-b`, then `d`. Reattach with `tmux attach -t exp`. The run has finished when it prints `done: results/*.md`.

## 4. Collect (on your laptop)
```bash
rsync -avz -e "ssh -i key.pem" ubuntu@<IP>:~/siemcrypt-experiments/results/ results/vm-m7i-2xlarge-<date>/
```
Commit that folder. Then **stop** the instance (EC2 → Instance state → Stop) to end compute charges.

## Runtime and memory (m7i.2xlarge)
| Step | Time | Notes |
|---|---|---|
| Synthetic E1–E5, E2 microbenchmarks, smoke | about 1 h | 8 workers |
| AIT fetch (first time only) | 30–50 min | about 1 GB of text logs into `~/data/ait-ldsv2` |
| AIT calibration, E1-A, E3 | about 3–4 h | full scenarios, 3 workers (up to about 10 GB each) |
| AIT E1-B injection sweep, E2 throughput | about 1–1.5 h | 36-hour windows, 8 workers |

The total is about 5–7 hours, so start it in the evening and collect the results the next morning.
- `HEAVY_WORKERS=3` keeps the full-scenario jobs within 32 GB. On a 64 GB instance with the same CPU (`r7i.2xlarge`), set `HEAVY_WORKERS=6`.
- `SKIP_AIT=1` runs only the synthetic experiments.
- If memory runs out anyway, the kernel kills a worker and Python reports `BrokenProcessPool`. Rerun with a smaller `HEAVY_WORKERS`.

## Notes
- A path with spaces must stay on one line when you paste it, or `cd` and `rsync` fail.
- Paillier is single-threaded big-integer arithmetic, so per-core speed decides `T_rand` and `T_Dec`. The Xeon VM is slower than an Apple laptop. Report the VM numbers.
