"""Published baselines B5 (PriSIEM), B7 (EVSEB) and B8 (MK-Tree) against SIEMCrypt (S),
each on the function it implements (DS2: E2, E3, E5).

Part A  ingestion on the same synthetic stream: time per event, bytes stored per event
        (B5: TFHE gate-count model with the gate time from tools/tfhe_gate_bench)
Part B  verification of k retrieved records out of n stored: hashes and time
        (S: MMR multiproof; B7: quaternary-root recomputation; B8: ancestor-assisted batch)
Part C  manipulation of stored data before verification: detected? (S results come from E5)
Part D  leakage of B7 under the E3 frequency attack: EVSEB's trapdoors never rotate, so the
        cloud accumulates per-keyword result counts over every epoch in which a per-entity
        query runs (the same correlation workload as S); compared with S on the same seeds

Usage:  python experiments/e_baselines.py [--quick] [--seeds 3] [--gate-us X]
Writes results/baselines_*.csv and baselines_summary.md.
"""

from __future__ import annotations

import argparse
import csv
import random
import statistics
import subprocess
import sys
import time
from collections import Counter, defaultdict
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import RESULTS, benign, config, generate, mean_sd, run, write_csv  # noqa: E402
from e1_accuracy import TEST  # noqa: E402
from leakage import aux_distribution, frequency_attack  # noqa: E402

from siemcrypt.baselines import prisiem  # noqa: E402
from siemcrypt.baselines.evseb import EVSEB  # noqa: E402
from siemcrypt.baselines.mktree import MKTree  # noqa: E402
from siemcrypt.baselines import zhang  # noqa: E402
from siemcrypt.crypto import mmr  # noqa: E402
from siemcrypt.data.synth import default_profiles_and_contexts  # noqa: E402
from siemcrypt.model import Event  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def by_epoch(events, epoch_len=3600.0):
    out = defaultdict(list)
    for ev in sorted(events, key=lambda x: x.ts):
        out[int(ev.ts // epoch_len) + 1].append(ev)
    return out


def rust_bench(name: str, args: list[str]) -> list[list[str]] | None:
    """Build and run tools/<name> (Rust, release); returns its CSV rows, or None without Rust."""
    bench = ROOT / "tools" / name
    try:
        subprocess.run(["cargo", "build", "--release", "-q"], cwd=bench, check=True)
        out = subprocess.run([str(bench / "target/release" / name), *args], capture_output=True,
                             text=True, check=True).stdout
        (RESULTS / f"{name}.csv").write_text(out)
        return [r for r in csv.reader(out.splitlines()) if r][1:]
    except (OSError, subprocess.CalledProcessError):
        return None


def gate_time_us(arg: float | None) -> tuple[float | None, str]:
    """T_gate from --gate-us, else from tools/tfhe_gate_bench."""
    if arg:
        return arg, "given"
    rows = rust_bench("tfhe_gate_bench", ["200"])
    t = next((float(r[2]) for r in rows or [] if r[0] == "T_gate"), None)
    return (t, "measured") if t else (None, "unavailable (install Rust: https://rustup.rs)")


def pairing_units() -> dict[str, float] | None:
    rows = rust_bench("pairing_bench", [])
    return {r[0]: float(r[2]) for r in rows} if rows else None


# ============================================================================ Part A
def ingest_costs(seed: int, t_gate: float | None) -> list[dict]:
    events, _ = generate(replace(TEST, seed=seed))
    n, epochs = len(events), by_epoch(events)
    profiles, contexts = default_profiles_and_contexts()
    rows = []
    s = run(config("S", seed=seed, precompute_workers=1), events, profiles, contexts)
    st = s.ee.stats
    rows.append(dict(system="S", seed=seed, ingest_us_per_event=(st["t_online"] + st["t_offline"]) / n * 1e6,
                     bytes_per_event=s.bus.total("ee", "cloud") / n, note="512-bit Paillier; see E2 for 2048-bit"))
    ev = EVSEB()
    for e, evs in epochs.items():
        ev.ingest_epoch(e, evs)
    stored = sum(len(r[2]) + len(r[4]) + 24 for r in ev.store.values()) + 64 * len(ev.dht)
    rows.append(dict(system="B7 EVSEB", seed=seed, ingest_us_per_event=ev.t["ingest"] / n * 1e6,
                     bytes_per_event=stored / n, note="AES, 4 keyword PRFs, Bloom, DHT, quaternary Merkle"))
    mk = MKTree()
    for e, evs in epochs.items():
        mk.ingest_epoch(e, evs)
    stored = sum(len(r[1]) + len(r[2]) + 12 + 32 + 64 for r in mk.store.values())
    rows.append(dict(system="B8 MK-Tree", seed=seed, ingest_us_per_event=mk.t["ingest"] / n * 1e6,
                     bytes_per_event=stored / n, note="AEAD, Ed25519 sign + verify, binary Merkle, certificates"))
    if t_gate:
        users = len({x.user for x in events})
        c = prisiem.cost(n, users, len(epochs), len(contexts), t_gate)
        rows.append(dict(system="B5 PriSIEM", seed=seed, ingest_us_per_event=c["seconds"] / n * 1e6,
                         bytes_per_event=None, note=f"{c['gates_per_event']:.0f} TFHE gates / event, 1 thread"))
    return rows


# ============================================================================ Part B
def _events(n: int, rng: random.Random) -> list[Event]:
    return [Event("src", f"u{rng.randrange(100)}", "r", "auth", {"count": 1}, rng.randbytes(200), i * 0.001)
            for i in range(n)]


def verification(n: int, k: int, seed: int, units: dict | None = None) -> list[dict]:
    rng = random.Random(seed)
    evs = _events(n, rng)
    idx = rng.sample(range(n), k)
    rows = []
    # S: MMR over n leaves, multiproof for k
    tree = mmr.MMR()
    for e in evs:
        tree.append(e.payload)
    proof = tree.multiprove(idx)
    hc = mmr.HashCounter()
    t0 = time.perf_counter()
    leaves = {i: mmr.leaf_hash(evs[i].payload, hc) for i in idx}  # rehash the retrieved records
    ok = mmr.multiverify(leaves, proof, tree.root(), tree.size, h=hc)
    rows.append(dict(system="S", n=n, k=k, hashes=hc.count, verify_ms=(time.perf_counter() - t0) * 1e3, ok=ok))
    ev = EVSEB()
    ev.ingest_epoch(1, evs)
    h0, t0 = ev.hashes, time.perf_counter()
    good, bad = ev.verify(set(idx))
    rows.append(dict(system="B7 EVSEB", n=n, k=k, hashes=ev.hashes - h0,
                     verify_ms=(time.perf_counter() - t0) * 1e3, ok=not bad))
    mk = MKTree()
    mk.ingest_epoch(1, evs)
    h0, t0 = mk.hashes, time.perf_counter()
    good, bad = mk.verify({(1, "auth", i) for i in idx})
    rows.append(dict(system="B8 MK-Tree", n=n, k=k, hashes=mk.hashes - h0,
                     verify_ms=(time.perf_counter() - t0) * 1e3, ok=not bad))
    if units:  # B9 audits a random third of the blocks (paper's setting), whatever k is
        c = zhang.audit_cost_us(max(1, n // 3), 8, units)
        rows.append(dict(system="B9 Zhang", n=n, k=k, hashes=None,
                         verify_ms=(c["csp_us"] + c["verify_us"]) / 1e3, ok=True))
    return rows


# ============================================================================ Part C
def tamper_matrix(seed: int) -> list[dict]:
    """Same manipulation types as E5 Part A, applied to B7 and B8 stores."""
    rng = random.Random(seed)
    evs = _events(2000, rng)
    rows = []

    def fresh():
        ev, mk = EVSEB(), MKTree()
        ev.ingest_epoch(1, evs[:1000]), ev.ingest_epoch(2, evs[1000:])
        mk.ingest_epoch(1, evs[:1000]), mk.ingest_epoch(2, evs[1000:])
        return ev, mk

    def flip(b):
        return bytes([b[0] ^ 1]) + b[1:]

    def ev_set(ev, lid, **kw):
        e, iv, ct, miv, mct = ev.store[lid]
        ev.store[lid] = (kw.get("e", e), iv, kw.get("ct", ct), miv, mct)

    cases = {}
    cases["modify payload ciphertext"] = (lambda ev, i: ev_set(ev, i, ct=flip(ev.store[i][2])),
                                          lambda mk, i: mk.store.__setitem__((1, "auth", i), (mk.store[(1, "auth", i)][0], flip(mk.store[(1, "auth", i)][1]), *mk.store[(1, "auth", i)][2:])))
    cases["substitute record"] = (lambda ev, i: ev_set(ev, i, ct=ev.store[(i + 1) % 1000][2]),
                                  lambda mk, i: mk.store.__setitem__((1, "auth", i), mk.store[(1, "auth", (i + 1) % 1000)]))

    def ev_reorder(ev, i):
        j = (i + 1) % 1000
        a, b = ev.store[i], ev.store[j]
        ev.store[i], ev.store[j] = (a[0], *b[1:]), (b[0], *a[1:])

    def mk_reorder(mk, i):
        j = (i + 1) % 1000
        mk.store[(1, "auth", i)], mk.store[(1, "auth", j)] = mk.store[(1, "auth", j)], mk.store[(1, "auth", i)]
    cases["reorder records"] = (ev_reorder, mk_reorder)

    def ev_splice(ev, i):
        ev_set(ev, i, ct=ev.store[1000 + i][2])

    def mk_splice(mk, i):
        mk.store[(1, "auth", i)] = mk.store[(2, "auth", i)]
    cases["cross-epoch splice"] = (ev_splice, mk_splice)

    def ev_dht(ev, i):  # cloud rewrites the record and its DHT hash consistently
        from siemcrypt.crypto.encoding import encode
        from siemcrypt.crypto.primitives import H
        ev_set(ev, i, ct=flip(ev.store[i][2]))
        ev.dht[H(encode(i))] = H(ev.store[i][2])

    def mk_dht(mk, i):  # cloud rewrites the record and every DHT node on its path
        from siemcrypt.crypto.primitives import H
        iv, ct, ad, d, sg = mk.store[(1, "auth", i)]
        ct = flip(ct)
        d = H(b"\x00" + iv + ct + ad)
        mk.store[(1, "auth", i)] = (iv, ct, ad, d, sg)
        lv = mk.levels[(1, "auth")]
        lv[-1][i] = d
        x = i
        for j in range(len(lv) - 2, -1, -1):
            x >>= 1
            lv[j][x] = H(b"\x01" + lv[j + 1][2 * x] + lv[j + 1][2 * x + 1])
    cases["rewrite record and off-chain proofs"] = (ev_dht, mk_dht)
    for name, (f_ev, f_mk) in cases.items():
        ev, mk = fresh()
        i = rng.randrange(1000)
        f_ev(ev, i)
        f_mk(mk, i)
        _, bad_ev = ev.verify({i})
        _, bad_mk = mk.verify({(1, "auth", i)})
        rows.append(dict(manipulation=name, seed=seed, **{"B7 EVSEB": bool(bad_ev), "B8 MK-Tree": bool(bad_mk)}))
    # omission: the cloud drops a matching record from a search result (B7 only has search)
    ev, _ = fresh()
    res = ev.search(["u:u7"])
    drop = next(iter(res))
    _, bad = ev.verify(res - {drop})
    rows.append(dict(manipulation="omit search result", seed=seed, **{"B7 EVSEB": bool(bad), "B8 MK-Tree": None}))
    return rows


def zhang_detection(seed: int, n: int = 48, audits: int = 20) -> list[dict]:
    """B9 audits sample l2 = n/3 blocks; detection of one manipulated block is probabilistic
    and the audit says only "non-integral", not which record."""
    rng = random.Random(seed)
    blocks = [rng.randbytes(1024) for _ in range(n)]
    other = [rng.randbytes(1024) for _ in range(n)]
    out = []

    def flip(b):
        return bytes([b[0] ^ 1]) + b[1:]
    cases = {"modify payload ciphertext": lambda z, i: z.blocks[1].__setitem__(i, flip(z.blocks[1][i])),
             "substitute record": lambda z, i: z.blocks[1].__setitem__(i, z.blocks[1][(i + 1) % n]),
             "reorder records": lambda z, i: z.blocks[1].__setitem__(slice(i, i + 2), z.blocks[1][i:i + 2][::-1]),
             "cross-epoch splice": lambda z, i: z.blocks[1].__setitem__(i, other[i])}
    for name, f in cases.items():
        z = zhang.ZhangAudit(s=8)
        z.upload(1, blocks)
        i = rng.randrange(n - 1)
        f(z, i)
        caught = sum(not z.audit(1, n // 3, f"{seed}-{name}-{a}".encode()) for a in range(audits))
        touched = 2 if name == "reorder records" else 1
        out.append(dict(manipulation=name, seed=seed, n=n, l2=n // 3, detected_audits=caught, audits=audits,
                        predicted=zhang.detection_probability(n, touched, n // 3)))
    return out


# ============================================================================ Part D
def evseb_leakage(seed: int) -> list[dict]:
    """Per-entity queries every epoch (the S correlation workload) against EVSEB's static
    trapdoors; the cloud ranks trapdoors by accumulated result counts and maps them to the
    auxiliary user ranking (same attack and auxiliary data as E3 for S)."""
    events, _ = generate(replace(TEST, seed=seed))
    aux, _ = generate(replace(benign(TEST), seed=1001))
    aux_rank = aux_distribution(aux, "U")
    ev = EVSEB()
    acc, truth = Counter(), {}
    tok_rate, vol_rate = [], []
    for e, evs in by_epoch(events).items():
        ev.ingest_epoch(e, evs)
        users = sorted({x.user for x in evs})
        for u in users:
            res = ev.search([f"u:{u}"])
            tw = ev.view[-1][0]
            acc[tw] = len({lid for lid in res})  # cumulative: index covers every epoch so far
            truth[tw] = u
        guess = {t: aux_rank[i] if i < len(aux_rank) else None for i, (t, _) in enumerate(acc.most_common())}
        cur = {ev.trapdoor(f"u:{u}"): u for u in users}
        ok = [t for t, u in cur.items() if guess.get(t) == u]
        tok_rate.append(len(ok) / len(cur))
        okset = {cur[t] for t in ok}
        vol_rate.append(sum(1 for x in evs if x.user in okset) / len(evs))
    s = run(config("S", seed=seed), events)
    fa = frequency_attack(s, aux_rank, "U")
    return [dict(system="B7 EVSEB", seed=seed, U_token_recovery=statistics.mean(tok_rate),
                 U_volume_recovery=statistics.mean(vol_rate), linkage=1.0),
            dict(system="S", seed=seed, U_token_recovery=fa["token_recovery"],
                 U_volume_recovery=fa["volume_recovery"], linkage=None)]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--seeds", type=int, default=3)
    ap.add_argument("--gate-us", type=float, default=None, help="TFHE gate time; default: run the Rust bench")
    args = ap.parse_args()
    seeds = list(range(1, (1 if args.quick else args.seeds) + 1))
    t0 = time.time()
    t_gate, how = gate_time_us(args.gate_us)
    md = ["# Published baselines: B5 PriSIEM, B7 EVSEB, B8 MK-Tree\n",
          f"Seeds {seeds}. TFHE gate time for B5: {f'{t_gate:,.0f} µs' if t_gate else 'n/a'} ({how}).\n"]

    rows = [r for sd in seeds for r in ingest_costs(sd, t_gate)]
    write_csv("baselines_ingest.csv", rows)
    md += ["## A. Ingestion on the synthetic test stream\n", "| System | µs / event | Bytes / event | Work per event |",
           "|---|---|---|---|"]
    for sy in dict.fromkeys(r["system"] for r in rows):
        sel = [r for r in rows if r["system"] == sy]
        md.append(f"| {sy} | {mean_sd([r['ingest_us_per_event'] for r in sel])} | "
                  f"{mean_sd([r['bytes_per_event'] for r in sel])} | {sel[0]['note']} |")
    if t_gate:
        md.append(f"\nB5 per-event cost uses {prisiem.gates_per_event(3)} gates (3 contexts × (Filter 256 + T-Count 295), "
                  f"PriSIEM Table 5), a lower bound; PriSIEM reports 1-4 tuples/s for its Rule-1 with 1-8 threads.")

    units = pairing_units()
    ns = [1_000, 10_000] if args.quick else [1_000, 10_000, 100_000]
    rows = [r for n in ns for k in (1, 10, 100, 1000) if k <= n for r in verification(n, k, 1, units)]
    write_csv("baselines_verify.csv", rows)
    md += ["\n## B. Verifying k records out of n\n",
           "| n | k | S hashes | S ms | B7 hashes | B7 ms | B8 hashes | B8 ms | B9 audit ms |",
           "|---|---|---|---|---|---|---|---|---|"]
    for n in ns:
        for k in (1, 10, 100, 1000):
            sel = {r["system"]: r for r in rows if r["n"] == n and r["k"] == k}
            if sel:
                b9 = f"{sel['B9 Zhang']['verify_ms']:.1f}" if "B9 Zhang" in sel else "n/a"
                md.append(f"| {n:,} | {k} | " + " | ".join(
                    f"{sel[s]['hashes']:,} | {sel[s]['verify_ms']:.2f}" for s in ("S", "B7 EVSEB", "B8 MK-Tree"))
                    + f" | {b9} |")
    md.append("\nB9 audits a random third of the n blocks whatever k is (the paper's setting); its time is the "
              "paper's cost formula (Section VII-A) with BN254 unit costs from tools/pairing_bench"
              + (f" (pairing {units['t_b']:.0f} µs, G1 exponentiation {units['t_x']:.0f} µs)." if units else
                 " (not available: install Rust)."))

    rows = [r for sd in seeds for r in tamper_matrix(sd)]
    write_csv("baselines_tamper.csv", rows)
    md += ["\n## C. Manipulation detected (S: see E5)\n", "| Manipulation | B7 EVSEB | B8 MK-Tree |", "|---|---|---|"]
    for m in dict.fromkeys(r["manipulation"] for r in rows):
        sel = [r for r in rows if r["manipulation"] == m]
        cell = lambda k: "n/a" if sel[0][k] is None else f"{sum(r[k] for r in sel)}/{len(sel)}"  # noqa: E731
        md.append(f"| {m} | {cell('B7 EVSEB')} | {cell('B8 MK-Tree')} |")

    zrows = [r for sd in seeds for r in zhang_detection(sd)]
    write_csv("baselines_tamper_b9.csv", zrows)
    md += ["\n## C2. B9 (Zhang et al.): share of audits that detect one manipulated record\n",
           "| Manipulation | Detected / audits | Predicted 1 - (1 - t/n)^l2 |", "|---|---|---|"]
    for m in dict.fromkeys(r["manipulation"] for r in zrows):
        sel = [r for r in zrows if r["manipulation"] == m]
        md.append(f"| {m} | {sum(r['detected_audits'] for r in sel)}/{sum(r['audits'] for r in sel)} | "
                  f"{sel[0]['predicted']:.2f} |")
    md.append(f"\nn = {zrows[0]['n']} blocks, l2 = {zrows[0]['l2']}; a failed audit marks the whole epoch file "
              "non-integral and does not identify the record.")

    rows = [r for sd in seeds for r in evseb_leakage(sd)]
    write_csv("baselines_leakage.csv", rows)
    md += ["\n## D. Frequency attack on entity tokens (same workload and auxiliary data as E3)\n",
           "| System | U tokens recovered | U volume recovered | Cross-epoch linkage |", "|---|---|---|---|"]
    for sy in ("S", "B7 EVSEB"):
        sel = [r for r in rows if r["system"] == sy]
        md.append(f"| {sy} | {mean_sd([r['U_token_recovery'] for r in sel])} | "
                  f"{mean_sd([r['U_volume_recovery'] for r in sel])} | "
                  f"{'1.000 (static trapdoors)' if sy != 'S' else 'see E3'} |")
    md.append(f"\nTotal time {time.time() - t0:.0f}s")
    (RESULTS / "baselines_summary.md").write_text("\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    main()
