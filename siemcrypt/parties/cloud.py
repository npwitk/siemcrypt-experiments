"""Cloud SIEM (honest-but-curious): stores protected records and the EPII, runs SG-HEF
(Phase 3) and attack-aware graph contraction (Phase 4), and answers investigation
queries with MMR multiproofs (Phase 6, Steps 2-3).

With cfg.acl (journal version) it also answers queries with authenticated posting lists
and an index proof against R_e^IDX, submits release requests Req_q to the EE instead of
the KA (verify-before-release), and attaches C_G to every graph update.

Implementation note: instead of receiving the MMR and index-dictionary nodes from the EE,
the cloud rebuilds them from the records and index entries it stores (same leaves, same
order), which yields identical nodes without the transfer.
"""

from __future__ import annotations

from collections import defaultdict

from .. import lineage
from ..bus import Bus
from ..crypto.mdict import MerkleDict
from ..crypto.mmr import MMR
from ..crypto.paillier import ZERO, Paillier
from ..protocol import DIMS, IndexEntry, ProtectedRecord, leaf_data
from .ka import KeyAuthority

DIM_IDX = {d: i for i, d in enumerate(DIMS)}


class CloudSIEM:
    def __init__(self, ka: KeyAuthority, bus: Bus, full_he: bool = False, acl: bool = False):
        self.ka, self.bus = ka, bus
        self.full_he = full_he  # B3: aggregate over the whole epoch (no SG-HEF scoping)
        self.acl = acl
        self.ee = None  # wired by the system (release requests under ACL)
        self._idx_cache: dict[int, MerkleDict] = {}
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

    def _idx(self, epoch: int) -> MerkleDict:
        if epoch not in self._idx_cache:
            self._idx_cache[epoch] = lineage.build_index(self.entries[r] for r in self.by_epoch[epoch])
        return self._idx_cache[epoch]

    def auth_candidates(self, epoch: int, tokens: dict[str, frozenset]) -> tuple[set, dict, object]:
        """Authenticated EPII retrieval: candidate rids, the queried posting lists, and one
        index multiproof for their keys (membership or non-membership)."""
        keys = lineage.query_keys(tokens)
        postings = {}
        for d, T in keys:
            lst = sorted(r[1] for r in self.epii[epoch][d].get(T, ()))
            if lst:
                postings[(d, T)] = lst
        proof = self._idx(epoch).prove([lineage.posting_key(d, T) for d, T in keys])
        Q = {(epoch, i) for i in lineage.candidates_from(tokens, postings, len(self.by_epoch[epoch]))}
        return Q, postings, proof

    def _sum(self, cts):
        acc = None
        for c in cts:
            acc = c if acc is None else self.he.add(acc, c)
            self.he_adds += 1
        return acc if acc is not None else ZERO  # empty sum: the identity, Enc(0; r = 1)

    def acl_request(self, q: dict, feat_index: dict[str, int]) -> dict:
        """Req_q (journal eq:release-request) with the commitments C_Q and C_A."""
        e = q["epoch"]
        Q, postings, proof = self.auth_candidates(e, q["tokens"])
        aggs, realness = self.aggregate(q, Q, feat_index)
        cp = self.checkpoints[e][0]
        chi = lineage.c_chi(q, cp)
        cq = lineage.c_q(chi, {r[1] for r in Q})
        return dict(Q=Q, postings=postings, proof=proof, aggs=aggs, realness=realness,
                    C_Q=cq, C_A=lineage.c_a(cq, q["feats"], aggs, realness, spec=lineage.c_spec(q)))

    def aggregate(self, q: dict, Q: set, feat_index: dict[str, int]):
        def smul_count(c, w):
            self.he_smuls += 1
            return self.he.smul(c, w)

        class _HE:
            smul = staticmethod(smul_count)

        return lineage.aggregate(q, Q, lambda r: (self.records[r].X, self.records[r].X0),
                                 lambda r: self.entries[r].tokens[3], feat_index, _HE, self._sum)

    def sghef(self, queries: list[dict], feat_index: dict[str, int]) -> list[dict]:
        out = []
        for q in queries:
            e = q["epoch"]
            if self.acl:
                req = self.bus.send("cloud", "ee", "release_req", self.acl_request(q, feat_index))
                z = self.ee.acl_release(q, req)
                if z is None:  # rejected: the slot stays (fixed dimension) with no evidence
                    z = self.ee.accepted[q["qid"]]
                out.append(self.bus.send("ee", "cloud", "evidence_z", z))
                continue
            Q = self.candidates(e, q["tokens"])
            if self.full_he:
                # B3: no index scoping; aggregate the masked slot over every record of the epoch
                base = q["slot"] * (len(feat_index) + 1)
                allr = self.by_epoch[e]
                aggs = {f: self._sum(self.records[r].X[base + feat_index[f]] for r in allr) for f in q["feats"]}
                realness = self._sum(self.records[r].X[base + len(feat_index)] for r in allr)
                self._release(out, q, e, Q, aggs, realness)
                continue
            aggs, realness = self.aggregate(q, Q, feat_index)
            self._release(out, q, e, Q, aggs, realness)
        return out

    def cohort(self, queries: list[dict], feat_index: dict[str, int]) -> dict[str, dict]:
        """AQRS cohort (journal v2 Phase 3, Steps 3-4): the same authenticated retrieval and
        HE aggregation for every member; the cloud cannot tell which member is real."""
        out = {q["qid"]: self.acl_request(q, feat_index) for q in queries}
        for q in queries:
            self.bus.send("cloud", "ee", "cohort_req", out[q["qid"]])
        return out

    def _release(self, out: list, q: dict, e: int, Q: set, aggs: dict, realness) -> None:
        self.bus.send("cloud", "ka", "release_req", (q["qid"], e, aggs, realness))
        y = self.ka.release(q["qid"], e, q["policy"], q["threshold"], aggs, realness)
        self.bus.send("ka", "cloud", "release", y)
        phi = (len(Q), len({self.entries[r].tokens[3] for r in Q}), len({self.entries[r].bucket for r in Q}))
        out.append(dict(qid=q["qid"], attack=q["attack"], epoch=e, Q=Q, y=y, phi=phi))

    # ================================================================ Phase 4: graph
    def contract(self, epoch: int, Z: list[dict]):
        """Attack-aware graph contraction (siemcrypt/lineage.py); C_G only with ACL."""
        return lineage.contract(Z, self.entries.__getitem__, self.graph_profiles.get(epoch, {}),
                                lineage.H if self.acl else None)

    def phase4(self, epoch: int, Z: list[dict]) -> tuple[list[tuple], float]:
        """Updates (T_u, a, z, refs, C_G) and the drift D_e from the token-independent epoch
        profile (eq:epoch-profile, eq:environment-drift)."""
        updates, mu = self.contract(epoch, Z)
        for upd in updates:
            self.bus.send("cloud", "ee", "update", upd)
        drift = lineage.drift(mu, self.mu_prev)
        self.mu_prev = mu
        self.bus.send("cloud", "ee", "drift", drift)
        return updates, drift

    # ================================================================ Phase 6: investigation
    def inv_query(self, epoch: int, tokens: dict[str, frozenset]) -> set:
        return self.candidates(epoch, tokens)

    def inv_query_auth(self, epoch: int, tokens: dict[str, frozenset]) -> tuple[set, dict, object]:
        """Historical retrieval with authenticated postings (journal eq:investigation-index-verification)."""
        return self.auth_candidates(epoch, tokens)

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
