"""Cloud SIEM (honest-but-curious): stores protected records and the EPII, runs SG-HEF
(Phase 3) and attack-aware graph contraction (Phase 4), and answers investigation
queries with MMR multiproofs (Phase 6, Steps 2-3).

Implementation note: instead of receiving the MMR nodes from the EE, the cloud rebuilds
each epoch MMR from the records and index entries it stores (same leaves, same order),
which yields identical nodes without the transfer.
"""

from __future__ import annotations

import math
from collections import defaultdict

from ..bus import Bus
from ..crypto.mmr import MMR
from ..crypto.paillier import Paillier
from ..model import GRAPH_FEATURES, Policy
from ..protocol import DIMS, IndexEntry, ProtectedRecord, leaf_data
from .ka import KeyAuthority

DIM_IDX = {d: i for i, d in enumerate(DIMS)}


class CloudSIEM:
    def __init__(self, ka: KeyAuthority, bus: Bus):
        self.ka, self.bus = ka, bus
        self.he = Paillier(ka.pk_h)
        self.records: dict[tuple, ProtectedRecord] = {}
        self.entries: dict[tuple, IndexEntry] = {}
        # EPII: epoch -> dim -> token -> set(rid); plus epoch -> bucket -> set(rid)
        self.epii = defaultdict(lambda: {d: defaultdict(set) for d in DIMS})
        self.by_bucket = defaultdict(lambda: defaultdict(set))
        self.by_epoch = defaultdict(list)
        self.checkpoints: dict[int, tuple[tuple, bytes]] = {}
        self._mmr_cache: dict[int, MMR] = {}
        self.graph_profiles: dict[int, dict[str, frozenset]] = {}
        self.mu_prev = None
        self.he_adds = 0
        self.he_smuls = 0

    # ================================================================ Phase 2: storage
    def receive_record(self, rec: ProtectedRecord, entry: IndexEntry) -> None:
        rid = rec.rid
        self.records[rid], self.entries[rid] = rec, entry
        for d, T in zip(DIMS, entry.tokens):
            self.epii[entry.epoch][d][T].add(rid)
        self.by_bucket[entry.epoch][entry.bucket].add(rid)
        self.by_epoch[entry.epoch].append(rid)

    def receive_checkpoint(self, cp: tuple, sig: bytes) -> None:
        self.checkpoints[cp[0]] = (cp, sig)

    def receive_graph_profiles(self, epoch: int, profiles: dict[str, frozenset]) -> None:
        self.graph_profiles[epoch] = profiles

    # ================================================================ Phase 3: SG-HEF
    def candidates(self, epoch: int, tokens: dict[str, frozenset]) -> set:
        """Q_q = intersection over specified dims of unions of posting lists (eq:candidate-set)."""
        sets = []
        for dim, toks in tokens.items():
            post = set()
            for T in toks:
                post |= self.epii[epoch][dim].get(T, set())
            sets.append(post)
        if not sets:
            return set(self.by_epoch[epoch])
        return set.intersection(*sets)

    def _sum(self, cts):
        acc = None
        for c in cts:
            acc = c if acc is None else self.he.add(acc, c)
            self.he_adds += 1
        return acc if acc is not None else self.he.encrypt(0)

    def sghef(self, queries: list[dict], feat_index: dict[str, int]) -> list[dict]:
        out = []
        for q in queries:
            e = q["epoch"]
            Q = self.candidates(e, q["tokens"])
            aggs = {}
            for f in q["feats"]:
                j = feat_index[f]
                if q["source_weights"]:
                    # cross-source fusion (eq:source-candidate .. eq:multisource-aggregate)
                    parts = []
                    for Ts, w in q["source_weights"].items():
                        sub = [self.records[r].X[j] for r in Q if self.entries[r].tokens[3] == Ts]
                        parts.append(self.he.smul(self._sum(sub), w))
                        self.he_smuls += 1
                    aggs[f] = self._sum(parts)
                else:
                    aggs[f] = self._sum(self.records[r].X[j] for r in Q)
            realness = self._sum(self.records[r].X0 for r in Q)
            self.bus.send("cloud", "ka", "release_req", (q["qid"], e, aggs, realness))
            y = self.ka.release(q["qid"], e, q["policy"], q["threshold"], aggs, realness)
            self.bus.send("ka", "cloud", "release", y)
            phi = (len(Q), len({self.entries[r].tokens[3] for r in Q}), len({self.entries[r].bucket for r in Q}))
            out.append(dict(qid=q["qid"], attack=q["attack"], epoch=e, Q=Q, y=y, phi=phi))
        return out

    # ================================================================ Phase 4: graph
    def phase4(self, epoch: int, Z: list[dict]) -> tuple[list[tuple], float]:
        Qall = set().union(*(z["Q"] for z in Z)) if Z else set()
        rel = {}  # (T_U, T_R, T_C) -> [n, sources, bucket histogram, refs]
        for rid in Qall:
            tu, tr, tc, ts = self.entries[rid].tokens
            r = rel.setdefault((tu, tr, tc), [0, set(), defaultdict(int), set()])
            r[0] += 1
            r[1].add(ts)
            r[2][self.entries[rid].bucket] += 1
            r[3].add(rid)
        updates = []
        profiles = self.graph_profiles.get(epoch, {})
        slots = defaultdict(list)
        for z in Z:
            slots[z["attack"]].append(z)
        for a, cat_tokens in profiles.items():
            proj = {k: v for k, v in rel.items() if k[2] in cat_tokens}  # eq:attack-projection
            by_entity = defaultdict(list)
            for k, v in proj.items():
                by_entity[k[0]].append((k, v))
            for tu, nbh in by_entity.items():
                srcs, buckets, res, refs = set(), set(), set(), set()
                deg = 0
                for (_, tr, _), (n, s, hist, rr) in nbh:
                    deg += n
                    srcs |= s
                    buckets |= set(hist)
                    res.add(tr)
                    refs |= rr
                g = [deg, len(res), len(srcs), len(nbh), len(buckets)]
                assert len(g) == len(GRAPH_FEATURES)
                # Fuse_{F_a}: one slot per context of class a; HIDE -> 0 (fixed dimension)
                y = []
                for z in slots[a]:
                    hit = bool(z["Q"] & refs)
                    y.append(sum(v for v in z["y"].values() if v is not None) if hit else 0.0)
                upd = (tu, a, g + y, frozenset(refs))
                updates.append(self.bus.send("cloud", "ee", "update", upd))
        # drift D_e from a token-independent epoch profile (eq:epoch-profile, eq:environment-drift)
        if rel:
            vals = list(rel.values())
            mu = [len(vals), sum(v[0] for v in vals) / len(vals),
                  sum(len(v[1]) for v in vals) / len(vals), sum(len(v[2]) for v in vals) / len(vals)]
        else:
            mu = [0.0, 0.0, 0.0, 0.0]
        if self.mu_prev is None:
            drift = 0.0
        else:
            num = math.sqrt(sum((a - b) ** 2 for a, b in zip(mu, self.mu_prev)))
            drift = num / (math.sqrt(sum(b * b for b in self.mu_prev)) + 1e-9)
        self.mu_prev = mu
        self.bus.send("cloud", "ee", "drift", drift)
        return updates, drift

    # ================================================================ Phase 6: investigation
    def inv_query(self, epoch: int, tokens: dict[str, frozenset]) -> set:
        return self.candidates(epoch, tokens)

    def _mmr(self, epoch: int) -> MMR:
        if epoch not in self._mmr_cache:
            t = MMR()
            for rid in sorted(self.by_epoch[epoch], key=lambda r: r[1]):
                t.append(leaf_data(self.records[rid], self.entries[rid]))
            self._mmr_cache[epoch] = t
        return self._mmr_cache[epoch]

    def evidence(self, refs: set, window: range) -> dict:
        """Per-epoch evidence packages Ev_tau (eq:epoch-evidence-package) and the
        checkpoints of every window epoch (for the chain check)."""
        by_ep = defaultdict(set)
        for rid in refs:
            by_ep[rid[0]].add(rid)
        packages = {}
        for tau, rids in by_ep.items():
            idx = [r[1] for r in rids]
            packages[tau] = dict(
                records={r: (self.records[r], self.entries[r]) for r in rids},
                proof=self._mmr(tau).multiprove(idx),
                checkpoint=self.checkpoints[tau],
            )
        cps = {tau: self.checkpoints[tau] for tau in window if tau in self.checkpoints}
        return self.bus.send("cloud", "sa", "evidence", dict(packages=packages, checkpoints=cps))
