"""End-to-end smoke run on synthetic data: Phases 1-6, alerts vs. ground truth.

Usage:  python experiments/smoke.py [--bits 512] [--epochs 6] [--events 600]
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from siemcrypt.data.synth import SynthConfig, default_profiles_and_contexts, generate  # noqa: E402
from siemcrypt.model import Config  # noqa: E402
from siemcrypt.system import SIEMCrypt  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bits", type=int, default=512)
    ap.add_argument("--epochs", type=int, default=6)
    ap.add_argument("--events", type=int, default=600)
    ap.add_argument("--gamma", type=float, default=1.0)
    ap.add_argument("--workers", type=int, default=1, help="offline randomizer workers; 0 = no precomputation")
    args = ap.parse_args()

    events, truth = generate(SynthConfig(epochs=args.epochs, events_per_epoch=args.events, n_users=80))
    profiles, contexts = default_profiles_and_contexts()
    s = SIEMCrypt(Config(paillier_bits=args.bits, agg_features=("count", "bytes"), gamma=args.gamma, seed=1,
                         precompute_workers=args.workers),
                  profiles, contexts)
    t0 = time.time()
    s.run(events)
    dt = time.time() - t0
    st = s.ee.stats
    print(f"{len(events)} events in {dt:.1f}s ({len(events) / dt:,.0f} ev/s); "
          f"decoys {st['decoy']} (delta={st['decoy'] / max(st['real'], 1):.2f}); KA decryptions {s.ka.decryptions}")
    off, on = st["t_offline"], st["t_online"]
    print(f"EE Phase 1-2: online {on:.2f}s ({len(events) / max(on, 1e-9):,.0f} ev/s), "
          f"offline randomizers {off:.2f}s; phases " +
          ", ".join(f"{k} {v:.2f}s" for k, v in s.timing.items()))
    print(f"bytes EE->cloud {s.bus.total('ee', 'cloud'):,}; messages in cloud view {len(s.bus.cloud_view):,}")
    alerted = {}
    for d in s.sa.alerts:
        alerted.setdefault((d.attack, s.ee.resolve_current(d.epoch, d.token)), []).append(d.epoch)
    print("\nGround truth:")
    for gt in truth:
        hit = alerted.get((gt.attack_class, gt.user))
        print(f"  {gt.attack_id:<6} {gt.kind:<13} {gt.user}  epochs {gt.epochs}  -> "
              f"{'DETECTED in ' + str(sorted(set(hit))) if hit else 'missed'}")
    attackers = {(gt.attack_class, gt.user) for gt in truth}
    fp = {k: v for k, v in alerted.items() if k[0] is not None and k not in attackers}
    print(f"False-positive (entity, class) pairs: {len(fp)} {sorted(k[1] for k in fp)[:10]}")
    unl = {k[1] for k in alerted if k[0] is None}
    print(f"Unclassified (screening) alerts for {len(unl)} entities")


if __name__ == "__main__":
    main()
