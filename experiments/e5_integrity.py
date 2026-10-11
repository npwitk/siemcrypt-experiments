"""E5: integrity and investigation (DS2 Section "Experiment 5", RQ5).

Part A  manipulation of stored evidence before an investigation; per manipulation type:
        detected? and was any affected record decrypted? (verify-before-decrypt)
Part B  multiproof vs. separate per-record Merkle paths: proof size (hashes, bytes) and
        verification time for k retrieved records out of n stored leaves
Part C  end-to-end investigation latency from alert to resolved identity

Usage:  python experiments/e5_integrity.py [--quick] [--bits 2048] [--trials 5]
Writes results/e5_tamper.csv, e5_proofs.csv, e5_latency.csv, e5_summary.md.
"""

from __future__ import annotations

import argparse
import os
import random
import statistics
import sys
import time
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import RESULTS, SynthConfig, config, generate, run, write_csv  # noqa: E402

from siemcrypt.crypto import mmr  # noqa: E402
from siemcrypt.crypto.encoding import encode  # noqa: E402
from siemcrypt.protocol import IndexEntry, ProtectedRecord  # noqa: E402

DATA = SynthConfig(epochs=4, events_per_epoch=300, n_users=40, n_low_and_slow=0, n_exfil=0)


# ============================================================================ Part A
def _alert(s):
    return next(d for d in s.sa.alerts if d.attack == "cred_access")


def _target(s, d, rng):
    """A provenance record of the alert (a record the investigation must retrieve)."""
    return rng.choice(sorted(d.provenance))


def m_record_ct(s, d, rng):
    rid = _target(s, d, rng)
    r = s.cloud.records[rid]
    s.cloud.records[rid] = replace(r, ct=bytes([r.ct[0] ^ 1]) + r.ct[1:])
    return {rid[0]}


def m_record_he(s, d, rng):
    rid = _target(s, d, rng)
    r = s.cloud.records[rid]
    s.cloud.records[rid] = replace(r, X=(s.cloud.he.add(r.X[0], r.X[0]),) + r.X[1:])
    return {rid[0]}


def m_index_entry(s, d, rng):
    rid = _target(s, d, rng)
    e = s.cloud.entries[rid]
    s.cloud.entries[rid] = replace(e, bucket=e.bucket + 1)
    return {rid[0]}


def m_substitute(s, d, rng):
    """Replace a record by another record of the same epoch, relabeled to its position."""
    rid = _target(s, d, rng)
    other = rng.choice([r for r in s.cloud.by_epoch[rid[0]] if r != rid])
    src, ent = s.cloud.records[other], s.cloud.entries[other]
    s.cloud.records[rid] = replace(src, iota=rid[1])
    s.cloud.entries[rid] = replace(ent, iota=rid[1])
    return {rid[0]}


def m_reorder(s, d, rng):
    """Swap the positions of two records of one epoch."""
    rid = _target(s, d, rng)
    other = rng.choice([r for r in s.cloud.by_epoch[rid[0]] if r != rid])
    a, b = s.cloud.records[rid], s.cloud.records[other]
    ea, eb = s.cloud.entries[rid], s.cloud.entries[other]
    s.cloud.records[rid], s.cloud.records[other] = replace(b, iota=rid[1]), replace(a, iota=other[1])
    s.cloud.entries[rid], s.cloud.entries[other] = replace(eb, iota=rid[1]), replace(ea, iota=other[1])
    return {rid[0]}


def m_cross_epoch(s, d, rng):
    """Splice a record of another epoch into the target position."""
    rid = _target(s, d, rng)
    other_ep = rng.choice([e for e in s.cloud.by_epoch if e != rid[0]])
    other = rng.choice(s.cloud.by_epoch[other_ep])
    s.cloud.records[rid] = replace(s.cloud.records[other], epoch=rid[0], iota=rid[1])
    s.cloud.entries[rid] = replace(s.cloud.entries[other], epoch=rid[0], iota=rid[1])
    return {rid[0]}


def m_rollback_checkpoint(s, d, rng):
    """Serve the (validly signed) checkpoint of the previous epoch for the alert epoch."""
    tau = d.epoch
    s.cloud.checkpoints[tau] = s.cloud.checkpoints[tau - 1]
    return {tau}


def m_forge_checkpoint(s, d, rng):
    tau = d.epoch
    (e, root, prev, n), sig = s.cloud.checkpoints[tau]
    s.cloud.checkpoints[tau] = ((e, os.urandom(len(root)), prev, n), sig)
    return {tau}


def m_truncate_checkpoint(s, d, rng):
    """Claim a shorter epoch (rollback of the MMR size) under the original signature."""
    tau = d.epoch
    (e, root, prev, n), sig = s.cloud.checkpoints[tau]
    s.cloud.checkpoints[tau] = ((e, root, prev, n - 1), sig)
    return {tau}


def m_forge_mmr_node(s, d, rng):
    """Corrupt an authentication node returned in the multiproof."""
    orig = s.cloud.evidence

    def evidence(refs, window):
        ev = orig(refs, window)
        for tau, pkg in ev["packages"].items():
            if pkg["proof"]:
                k = rng.choice(sorted(pkg["proof"]))
                pkg["proof"][k] = os.urandom(32)
                evidence.hit = {tau}
                break
        return ev

    evidence.hit = set()
    s.cloud.evidence = evidence
    return evidence


def m_omit_requested(s, d, rng):
    """Drop a requested (rid-addressed) provenance record from the evidence."""
    rid = _target(s, d, rng)
    orig = s.cloud.evidence

    def evidence(refs, window):
        return orig(refs - {rid}, window)

    s.cloud.evidence = evidence
    return {rid[0]}


def m_omit_search(s, d, rng):
    """Known limitation: omit matching records from the historical search results."""
    orig = s.cloud.inv_query
    dropped = []

    def inv_query(epoch, tokens):
        res = orig(epoch, tokens)
        extra = sorted(res - d.provenance)
        dropped.extend(extra)
        return res - set(extra)

    s.cloud.inv_query = inv_query
    return dropped


MANIPULATIONS = {
    "modify payload ciphertext": m_record_ct,
    "modify HE feature": m_record_he,
    "modify index entry": m_index_entry,
    "substitute record": m_substitute,
    "reorder records": m_reorder,
    "cross-epoch splice": m_cross_epoch,
    "rollback checkpoint (replay)": m_rollback_checkpoint,
    "forge checkpoint root": m_forge_checkpoint,
    "truncate MMR size": m_truncate_checkpoint,
    "forge MMR node": m_forge_mmr_node,
    "omit requested record": m_omit_requested,
    "omit search result (limitation)": m_omit_search,
}


def tamper_trial(name: str, seed: int) -> dict:
    events, _ = generate(replace(DATA, seed=seed))
    s = run(config("S", seed=seed), events)
    d = _alert(s)
    if name.startswith("omit search"):
        d = replace(d, attack=None)  # entity-wide historical search: results beyond provenance
    rng = random.Random(seed)
    clean = s.investigate(d)
    s.cloud._mmr_cache.clear()
    hit = MANIPULATIONS[name](s, d, rng)
    s.cloud._mmr_cache.clear()
    inv = s.investigate(d)
    if callable(hit):  # forge MMR node: epochs known after the call
        hit = hit.hit
    if name.startswith("omit search"):
        detected = bool(inv.failed_epochs)
        affected_decrypted = False
        lost = len(clean.plaintexts) - len(inv.plaintexts)
    else:
        detected = bool(set(inv.failed_epochs) & set(hit))
        affected_decrypted = bool(set(inv.verified_epochs) & set(hit))
        lost = None
    return dict(manipulation=name, seed=seed, detected=int(detected), affected_decrypted=int(affected_decrypted),
                clean_ok=int(not clean.failed_epochs), failed_epochs=len(inv.failed_epochs),
                verified_epochs=len(inv.verified_epochs), missing=inv.missing_records, plaintexts_lost=lost)


# ============================================================================ Part B
def proof_sweep(ns: list[int], ks: list[int], reps: int) -> list[dict]:
    rows = []
    rng = random.Random(0)
    for n in ns:
        t = mmr.MMR()
        leaves = [mmr.leaf_hash(encode(i, os.urandom(32))) for i in range(n)]
        for lh in leaves:
            t.append_leaf_hash(lh)
        root = t.root()
        for k in ks:
            if k > n:
                continue
            idx = rng.sample(range(n), k)
            mp = t.multiprove(idx)
            sep = [t.multiprove([i]) for i in idx]
            sub = {i: leaves[i] for i in idx}

            def tm(fn):
                xs = []
                for _ in range(reps):
                    t0 = time.perf_counter()
                    assert fn()
                    xs.append(time.perf_counter() - t0)
                return statistics.median(xs) * 1e3

            ms_multi = tm(lambda: mmr.multiverify(sub, mp, root, n))
            ms_sep = tm(lambda: all(mmr.multiverify({i: leaves[i]}, p, root, n) for i, p in zip(idx, sep)))
            hs_sep = sum(len(p) for p in sep)
            rows.append(dict(n=n, k=k, multiproof_hashes=len(mp), separate_hashes=hs_sep,
                             multiproof_bytes=32 * len(mp), separate_bytes=32 * hs_sep,
                             multiverify_ms=ms_multi, separate_verify_ms=ms_sep))
            print(f"  n={n:>8} k={k:>5}: {len(mp):>6} vs {hs_sep:>7} hashes; "
                  f"{ms_multi:8.2f} vs {ms_sep:8.2f} ms", flush=True)
    return rows


# ============================================================================ Part C
def latency(bits: int, workers: int, seed: int = 1) -> list[dict]:
    events, _ = generate(SynthConfig(epochs=6, events_per_epoch=600, n_users=80, seed=seed))
    s = run(config("S", paillier_bits=bits, precompute_workers=workers, seed=seed), events)
    rows = []
    for d in [d for d in s.sa.alerts if d.attack][:10]:
        b0 = sum(s.bus.bytes.values())
        t0 = time.perf_counter()
        inv = s.investigate(d)
        dt = time.perf_counter() - t0
        rows.append(dict(bits=bits, attack=d.attack, window=len(inv.window), verified_records=inv.verified_records,
                         decoys_dropped=inv.decoys_dropped, plaintexts=len(inv.plaintexts),
                         identity_resolved=int(inv.identity is not None), latency_ms=dt * 1e3,
                         bytes=sum(s.bus.bytes.values()) - b0))
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--trials", type=int, default=5)
    ap.add_argument("--bits", type=int, default=2048, help="key size for Part C")
    ap.add_argument("--workers", type=int, default=8)
    args = ap.parse_args()
    trials = 2 if args.quick else args.trials
    t0 = time.time()

    from concurrent.futures import ProcessPoolExecutor

    jobs = [(m, sd) for m in MANIPULATIONS for sd in range(1, trials + 1)]
    with ProcessPoolExecutor(args.workers) as ex:
        rowsA = list(ex.map(tamper_trial, *zip(*jobs)))
    write_csv("e5_tamper.csv", rowsA)
    print(f"part A done in {time.time() - t0:.0f}s", flush=True)

    ns = [1_000, 10_000, 100_000] if args.quick else [1_000, 10_000, 100_000, 1_000_000]
    rowsB = proof_sweep(ns, [1, 10, 100, 1000], reps=3 if args.quick else 7)
    write_csv("e5_proofs.csv", rowsB)

    rowsC = latency(512 if args.quick else args.bits, args.workers)
    write_csv("e5_latency.csv", rowsC)

    md = ["# E5 results (synthetic data)\n", "## Part A: manipulation detection\n",
          "| Manipulation | Detected | Affected record decrypted | Clean run verified |", "|---|---|---|---|"]
    for m in MANIPULATIONS:
        sel = [r for r in rowsA if r["manipulation"] == m]
        md.append(f"| {m} | {sum(r['detected'] for r in sel)}/{len(sel)} | "
                  f"{sum(r['affected_decrypted'] for r in sel)}/{len(sel)} | {sum(r['clean_ok'] for r in sel)}/{len(sel)} |")
    om = [r for r in rowsA if r["manipulation"].startswith("omit search")]
    md.append(f"\nOmitted search results: {sum(r['plaintexts_lost'] for r in om)} plaintexts silently lost over "
              f"{len(om)} trials (inclusion proofs cannot detect omission).\n")
    md += ["## Part B: multiproof vs. separate paths\n",
           "| n | k | Multiproof hashes | Separate hashes | Multiverify (ms) | Separate (ms) |", "|---|---|---|---|---|---|"]
    md += [f"| {r['n']:,} | {r['k']} | {r['multiproof_hashes']:,} | {r['separate_hashes']:,} | "
           f"{r['multiverify_ms']:.2f} | {r['separate_verify_ms']:.2f} |" for r in rowsB]
    md += ["", f"## Part C: investigation latency ({rowsC[0]['bits'] if rowsC else '-'}-bit keys)\n",
           "| Attack | Window | Verified records | Plaintexts | Identity | Latency (ms) | Bytes |",
           "|---|---|---|---|---|---|---|"]
    md += [f"| {r['attack']} | {r['window']} | {r['verified_records']} | {r['plaintexts']} | "
           f"{'yes' if r['identity_resolved'] else 'no'} | {r['latency_ms']:.1f} | {r['bytes']:,} |" for r in rowsC]
    md.append(f"\nTotal time {time.time() - t0:.0f}s")
    (RESULTS / "e5_summary.md").write_text("\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    main()
