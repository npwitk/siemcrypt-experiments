"""Journal Experiments 2 and 5 (figures): authenticated retrieval and ACL scalability.

One outsourced epoch of N protected records (2048-bit Paillier ciphertexts, |J| = 2 features
plus the realness indicator), indexed by four token dimensions plus buckets. A query selects
q = |Q_q| records through one category token. Per query we time, separately:
  retrieve   cloud: posting lookup, candidate set and index multiproof (Authenticated EPII)
  aggregate  cloud: SG-HEF aggregates over the candidates
  verify_idx EE: VerifyIDX against R^IDX and candidate recomputation
  acl        EE: complete verify-before-release (VerifyIDX + candidate recomputation +
             commitments + scoped HE recomputation), i.e. Algorithm alg:acl
  full       EE: re-execution over the whole epoch (predicate check + aggregation over all N
             records), the alternative ACL avoids
plus hashes, HE additions and the bytes of the posting lists and proof sent to the EE.
Ciphertexts are random elements of Z_{N^2}^*: homomorphic additions cost the same as on
real ciphertexts, and nothing is decrypted.

Sweeps: (a) N fixed, selectivity q/N in {0.1%, 0.5%, 1%, 5%, 10%, 25%};
        (b) q fixed, N growing; index construction time per N (EE, end of epoch).

Usage:  python experiments/e2_acl_scale.py [--quick] [--n 100000] [--q 1000] [--reps 5]
Writes results/e2_acl_scale.csv and e2_acl_scale.md.
"""

from __future__ import annotations

import argparse
import os
import random
import statistics
import sys
import time
from pathlib import Path

import gmpy2

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import RESULTS, write_csv  # noqa: E402

from siemcrypt import lineage  # noqa: E402
from siemcrypt.crypto import paillier  # noqa: E402
from siemcrypt.crypto.mmr import HashCounter  # noqa: E402
from siemcrypt.model import Policy  # noqa: E402
from siemcrypt.protocol import IndexEntry  # noqa: E402

FEATS = ("count", "bytes")
FI = {f: j for j, f in enumerate(FEATS)}


class Repo:
    """One epoch: entries, ciphertexts, index and checkpoint."""

    def __init__(self, N: int, q: int, pk, rng: random.Random):
        self.N = N
        tok = lambda: os.urandom(32)  # noqa: E731
        users = [tok() for _ in range(max(N // 50, 10))]
        res = [tok() for _ in range(max(N // 200, 10))]
        cats = [tok() for _ in range(40)]
        srcs = [tok() for _ in range(4)]
        self.target = tok()
        hit = set(rng.sample(range(N), q))
        n2 = pk.n2
        self.entries, self.X = {}, {}
        for i in range(N):
            c = self.target if i in hit else rng.choice(cats)
            self.entries[i] = IndexEntry((rng.choice(users), rng.choice(res), c, rng.choice(srcs)), i // 500, 1, i)
            self.X[i] = (tuple(gmpy2.mpz(rng.getrandbits(n2.bit_length() - 1)) for _ in FEATS),
                         gmpy2.mpz(rng.getrandbits(n2.bit_length() - 1)))
        t0 = time.perf_counter()
        self.index = lineage.build_index(self.entries.values())
        self.t_build = time.perf_counter() - t0
        self.postings = lineage.postings_of(self.entries.values())
        self.cp = (1, os.urandom(32), self.index.root(), os.urandom(32), N)
        self.q = dict(qid="q", attack="a", epoch=1, slot=0, tokens={"C": frozenset({self.target})}, feats=FEATS,
                      source_weights={}, policy=Policy.VALUE, threshold=0.0)


def bench(repo: Repo, he, reps: int) -> dict:
    q, cp = repo.q, repo.cp
    adds = [0]

    def summer(cts):
        acc = None
        for c in cts:
            acc = c if acc is None else he.add(acc, c)
            adds[0] += 1
        return acc

    src = lambda i: repo.entries[i].tokens[3]  # noqa: E731
    out = {k: [] for k in ("retrieve", "aggregate", "verify_idx", "acl", "full")}
    for _ in range(reps):
        # cloud: authenticated retrieval
        t0 = time.perf_counter()
        keys = lineage.query_keys(q["tokens"])
        P = {k: repo.postings[k] for k in keys if k in repo.postings}
        proof = repo.index.prove([lineage.posting_key(d, T) for d, T in keys])
        Q = lineage.candidates_from(q["tokens"], P, repo.N)
        out["retrieve"].append(time.perf_counter() - t0)
        # cloud: aggregation and commitments
        t0 = time.perf_counter()
        aggs, real = lineage.aggregate(q, Q, repo.X.__getitem__, src, FI, he, summer)
        chi = lineage.c_chi(q, cp)
        cq = lineage.c_q(chi, Q)
        ca = lineage.c_a(cq, FEATS, aggs, real)
        out["aggregate"].append(time.perf_counter() - t0)
        # EE: VerifyIDX + candidate recomputation
        hc = HashCounter()
        t0 = time.perf_counter()
        assert lineage.verify_postings(cp[2], q["tokens"], P, proof, hc)
        Q2 = lineage.candidates_from(q["tokens"], P, repo.N)
        t_idx = time.perf_counter() - t0
        out["verify_idx"].append(t_idx)
        # EE: rest of Algorithm alg:acl
        a0 = adds[0]
        t0 = time.perf_counter()
        assert Q2 == Q and lineage.c_q(lineage.c_chi(q, cp, hc), Q2, hc) == cq
        aggs2, real2 = lineage.aggregate(q, Q2, repo.X.__getitem__, src, FI, he, summer)
        assert all(aggs2[f] == aggs[f] for f in FEATS) and real2 == real
        assert lineage.c_a(cq, FEATS, aggs2, real2, hc) == ca
        lineage.acl_record(chi, cq, ca, hc)
        out["acl"].append(t_idx + time.perf_counter() - t0)
        acl_adds = adds[0] - a0
        # EE: full re-execution over the epoch
        t0 = time.perf_counter()
        Qf = {i for i, ent in repo.entries.items() if ent.tokens[2] in q["tokens"]["C"]}
        lineage.aggregate(q, Qf, repo.X.__getitem__, src, FI, he, summer)
        out["full"].append(time.perf_counter() - t0)
    ct_bytes = (int(he.pk.n2.bit_length()) + 7) // 8
    row = {f"{k}_ms": statistics.median(v) * 1e3 for k, v in out.items()}
    row.update(N=repo.N, q=len(Q), selectivity=len(Q) / repo.N, acl_hashes=hc.count, acl_he_adds=acl_adds,
               proof_hashes=proof.size(), ee_bytes=32 * proof.size() + 8 * sum(len(v) for v in P.values())
               + 2 * 32 * len(proof.entries) + ct_bytes * (len(FEATS) + 1) + 3 * 32,
               index_build_ms=repo.t_build * 1e3, index_keys=repo.index.n)
    return row


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--n", type=int, default=100_000)
    ap.add_argument("--q", type=int, default=1_000)
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--bits", type=int, default=2048)
    args = ap.parse_args()
    if args.quick:
        args.n, args.q, args.reps = 10_000, 100, 2
    t0 = time.time()
    pk, _ = paillier.keygen(args.bits)
    he = paillier.Paillier(pk)
    rng = random.Random(0)
    rows = []
    sels = [0.001, 0.005, 0.01, 0.05, 0.10, 0.25]
    for sel in sels:
        repo = Repo(args.n, max(1, int(sel * args.n)), pk, rng)
        rows.append(dict(sweep="selectivity", **bench(repo, he, args.reps)))
        print(rows[-1], flush=True)
    Ns = [args.n // 10, args.n // 4, args.n // 2, args.n, args.n * 2]
    for N in Ns:
        repo = Repo(N, args.q, pk, rng)
        rows.append(dict(sweep="repository", **bench(repo, he, args.reps)))
        print(rows[-1], flush=True)
    write_csv("e2_acl_scale.csv", rows)
    import platform
    md = [f"# Authenticated retrieval and ACL scalability ({platform.node()}, {args.bits}-bit Paillier, "
          f"|J| = {len(FEATS)} + realness, median of {args.reps})\n"]
    cols = [("q", "q"), ("selectivity", "q/N"), ("retrieve_ms", "EPII retrieve (ms)"),
            ("aggregate_ms", "SG-HEF aggregate (ms)"), ("verify_idx_ms", "VerifyIDX (ms)"), ("acl_ms", "ACL total (ms)"),
            ("full_ms", "Full recompute (ms)"), ("acl_hashes", "ACL hashes"), ("acl_he_adds", "ACL HE adds"),
            ("ee_bytes", "Bytes to EE")]
    for sweep, title, first in (("selectivity", f"(a) N = {args.n:,}, varying selectivity", None),
                                ("repository", f"(b) q = {args.q:,}, varying N", ("N", "N"))):
        cs = ([first] if first else [("N", "N")]) + cols
        md += [f"\n## {title}\n", "| " + " | ".join(c[1] for c in cs) + " | Index build (ms) |",
               "|" + "---|" * (len(cs) + 1)]
        for r in rows:
            if r["sweep"] != sweep:
                continue
            cells = []
            for k, _ in cs:
                v = r[k]
                cells.append(f"{v:.2%}" if k == "selectivity" else (f"{v:,.2f}" if isinstance(v, float) else f"{v:,}"))
            md.append("| " + " | ".join(cells) + f" | {r['index_build_ms']:,.0f} |")
    md.append(f"\nTotal time {time.time() - t0:.0f}s")
    (RESULTS / "e2_acl_scale.md").write_text("\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    main()
