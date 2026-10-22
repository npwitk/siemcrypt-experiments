"""Edge Encryptor (EE): the trusted component that sees plaintext.

Phase 1  normalization is done by the loaders; here: tokens (eq:tokens), AES-GCM payloads
         (eq:aes-gcm), HE features (eq:he), realness indicator (eq:realness-indicator),
         frequency-hiding decoy padding (eq:tier, eq:padding-deficit, eq:decoy-count), or the
         journal's LAPH (siemcrypt/laph.py) and fixed padding over real values.
Phase 2  index entries (eq:index-entry), MMR commitment (eq:mmr-leaf), authenticated EPII root
         and checkpoints CP_e = (e, R^MMR, R^IDX, H(CP_{e-1}), n_e) (journal eq:checkpoint),
         TD registration (eq:token-mapping).
Phase 3  protected queries (eq:protected-query); with cfg.acl, verify-before-release ACL
         (journal Algorithm alg:acl) before the KA release.
Phase 4  with cfg.acl, graph-lineage verification of the cloud's updates (C_G).
Phase 5  trusted history, adaptive retention, scoring, alerts (eq:adaptive-decay ...
         eq:alert-descriptor); state commitments C_H with cfg.acl; label-free screening
         (eq:sketch-keys ... eq:unlabeled-alert).
Phase 6  historical token derivation (eq:historical-entity-token, eq:investigation-query).
"""

from __future__ import annotations

import math
import random
import statistics
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from .. import lineage
from ..bus import Bus
from ..crypto.cms import CountMin
from ..crypto.encoding import FixedPoint, encode
from ..crypto.mmr import MMR
from ..crypto.mmr import HashCounter
from ..crypto.paillier import Paillier
from ..crypto.primitives import H, aead_encrypt, prf_token
from ..laph import ExposureTracker, plan_decoys
from ..model import GRAPH_FEATURES, AttackProfile, Config, Context, Event
from ..protocol import DIMS, IndexEntry, ProtectedRecord, aead_ad, leaf_data
from .ka import GENESIS, KeyAuthority
from .td import TokenDirectory


def tier(c: int, gamma: float) -> int:
    """Tier_gamma(c) = min{ceil(gamma^k) : k in N_0, ceil(gamma^k) >= c}, c >= 1 (eq:tier)."""
    if c < 1:
        raise ValueError("tier defined for c >= 1")
    k, v = 0, 1
    while v < c:
        k += 1
        v = math.ceil(gamma**k)
    return v


def _sigmoid(x: float) -> float:
    """Logistic function, stable for any magnitude of x (math.exp overflows past ~709)."""
    if x >= 0:
        return 1.0 / (1.0 + math.exp(-x))
    ex = math.exp(x)
    return ex / (1.0 + ex)


@dataclass
class Descriptor:
    """Desc_{u,a}^(e) = (e, T_u, a, S, ell, Prov), eq:alert-descriptor; a=None for
    unclassified alerts (eq:unlabeled-alert-descriptor)."""

    epoch: int
    token: bytes
    attack: str | None
    score: float
    horizon: int | None
    provenance: frozenset
    state_commitment: bytes | None = None  # C_H with cfg.acl


@dataclass
class _Pending:
    tokens: tuple[bytes, bytes, bytes, bytes]
    feats: dict
    payload: bytes
    delta: int
    user: str | None


@dataclass
class _PairState:
    h: list[float]
    R: float = 0.0
    prov: set = field(default_factory=set)
    C_H: bytes = GENESIS
    zs: list = field(default_factory=list)  # NoContract: explicit (epoch, z) history


class EdgeEncryptor:
    def __init__(self, cfg: Config, ka: KeyAuthority, td: TokenDirectory, bus: Bus,
                 profiles: dict[str, AttackProfile], contexts: list[Context]):
        if cfg.epoch_len % cfg.bucket_len:
            raise ValueError("epoch_len must be a multiple of bucket_len")
        self.cfg, self.ka, self.td, self.bus = cfg, ka, td, bus
        self.profiles, self.contexts = profiles, contexts
        self.cloud = None  # wired by the system
        self.sa = None
        self.he = Paillier(ka.pk_h)
        self.fp = FixedPoint(int(ka.pk_h.n), cfg.frac_bits)
        self.rng = random.Random(cfg.seed) if cfg.seed is not None else random.SystemRandom()
        # per-epoch state
        self.epoch: int | None = None
        self.keys: dict[str, bytes] = {}
        self.mmr: MMR | None = None
        self.prev_cp_hash = GENESIS
        self.checkpoint: tuple | None = None
        self.epoch_entries: dict[int, IndexEntry] = {}  # iota -> entry, current epoch
        self.epoch_X: dict[int, tuple] = {}             # iota -> (X, X0), current epoch (cfg.acl)
        self.accepted: dict[str, dict] = {}             # qid -> accepted Phase 3 evidence (cfg.acl)
        self.mu_prev = None
        self.exposure = ExposureTracker(cfg) if cfg.padding == "laph" else None
        if cfg.acl and cfg.full_he:
            raise ValueError("ACL is defined for SG-HEF, not for the full-HE baseline")
        self._tok_cache: dict[tuple[int, str, str], bytes] = {}
        self.user_of: dict[int, dict[bytes, str]] = defaultdict(dict)  # epoch -> T_U -> u
        self.dummy: dict[int, set[bytes]] = defaultdict(set)
        # bucket state
        self.bucket: int | None = None
        self.bucket_events: list[Event] = []
        # Phase 5 state, keyed by (user, attack)
        self.state: dict[tuple[str, str], _PairState] = {}
        # screening state
        self.cms_cur = CountMin.for_error(cfg.cms_eps, cfg.cms_delta)
        self.cms_base = self.cms_cur.like()
        self.buckets_seen = 0
        self.chi2_threshold = statistics.NormalDist().inv_cdf(1 - cfg.alpha_fp / 2) ** 2
        # statistics for experiments (t_offline / t_online in seconds)
        self.stats = Counter()
        # evaluation-only ground truth; no protocol step reads these
        self.score_log: list[tuple] = []  # (epoch, user, attack, S, z, h^(e-1))
        self.decoy_rids: set[tuple[int, int]] = set()
        self.horizon_log: list[tuple] = []  # (epoch, user, attack, ell, lambda)
        self.acl_log: list[dict] = []       # per verification: kind, ok, seconds, hashes, he_adds

    # ================================================================ helpers
    def token(self, dim: str, value: str, epoch: int | None = None,
              keys: dict[str, bytes] | None = None) -> bytes:
        e = self.epoch if epoch is None else epoch
        ck = (e, dim, value)
        if ck not in self._tok_cache:
            self._tok_cache[ck] = prf_token((keys or self.keys)[dim], value)
            self.stats["prf"] += 1
        return self._tok_cache[ck]

    def precompute(self, n: int) -> None:
        """Offline phase: precompute Paillier randomizers (timed separately)."""
        t0 = time.perf_counter()
        self.he.precompute(n, self.cfg.precompute_workers)
        self.stats["t_offline"] += time.perf_counter() - t0

    # ================================================================ Phase 1/2: epochs and ingestion
    def start_epoch(self, epoch: int) -> None:
        self.epoch = epoch
        self.keys = self.bus.send("ka", "ee", "epoch_keys", self.ka.epoch_keys(epoch))
        self.mmr = MMR()
        self.epoch_entries, self.epoch_X, self.accepted = {}, {}, {}

    def ingest(self, ev: Event) -> None:
        b = int(ev.ts // self.cfg.bucket_len)
        if self.bucket is not None and b != self.bucket:
            self.close_bucket()
        self.bucket = b
        self.bucket_events.append(ev)
        if self.cfg.screening:
            self.cms_cur.update(H(ev.user.encode()))
            self.cms_cur.update(H(encode(ev.user, ev.res, ev.cat)))

    def _real_value_decoys(self, events: list[Event], real_lengths: list[int]) -> list[_Pending]:
        """LAPH (cfg.padding == "laph") or fixed padding over real values ("fixed")."""
        if self.cfg.padding == "laph":
            gamma_of = {k: self.exposure.gamma(L) for k, L in self.exposure.scores(events).items()}
        else:
            gamma_of = {(d, v): self.cfg.gamma for ev in events for d, v in (("U", ev.user), ("R", ev.res))}
        out = []
        for u, r, c, s in plan_decoys(events, gamma_of, self.rng):
            toks = tuple(self.token(d, v) for d, v in zip(DIMS, (u, r, c, s)))
            n = self.rng.choice(real_lengths)
            out.append(_Pending(toks, {}, self.rng.randbytes(n) if hasattr(self.rng, "randbytes") else bytes(n), 1, None))
        return out

    def _decoys(self, real_tokens: list[tuple], real_lengths: list[int]) -> list[_Pending]:
        """Frequency-hiding padding for one bucket (Phase 1, Step 5)."""
        if self.cfg.padding == "laph" or (self.cfg.padding == "fixed" and self.cfg.gamma > 1):
            return self._real_value_decoys(self.bucket_events, real_lengths) if real_tokens else []
        g = self.cfg.gamma
        if g <= 1 or not real_tokens:
            return []
        n_real = len(real_tokens)
        lists = {}
        need = 0
        for di, dim in ((0, "U"), (1, "R")):
            counts = Counter(t[di] for t in real_tokens)
            zeta = {T: tier(c, g) - c for T, c in counts.items()}
            lists[dim] = [T for T, z in zeta.items() for _ in range(z)]
            need = max(need, len(lists[dim]))
        n_dec = tier(n_real + need, g) - n_real
        for dim in ("U", "R"):
            lst = lists[dim]
            for j in range(n_dec - len(lst)):
                t = prf_token(self.keys[dim], encode("dum", self.bucket, j))  # eq:dummy-token
                self.stats["prf"] += 1
                self.dummy[self.epoch].add(t)
                lst.append(t)
            self.rng.shuffle(lst)
        out = []
        for k in range(n_dec):
            _, _, tc, ts = self.rng.choice(real_tokens)  # real (category, source) pair
            out.append(_Pending((lists["U"][k], lists["R"][k], tc, ts), {},
                                self.rng.randbytes(self.rng.choice(real_lengths))
                                if hasattr(self.rng, "randbytes") else bytes(self.rng.choice(real_lengths)),
                                1, None))
        return out

    def _he_per_record(self) -> int:
        F = len(self.cfg.agg_features)
        return len(self.contexts) * (F + 1) + 1 if self.cfg.full_he else F + 1

    def _full_he_features(self, p: _Pending) -> tuple:
        """B3 (full-HE baseline): for every context q, Enc(w * x_f * m_q) for each feature f and
        Enc((1 - delta) * m_q), where m_q = 1 if the record satisfies q's predicates and w is the
        source weight (1 if q has none). Laid out as slot q * (|J_AGG| + 1) + j."""
        out = []
        for c in self.contexts:
            m = 1
            for di, vals in enumerate((c.users, c.resources, c.categories, c.sources)):
                if vals and p.tokens[di] not in {self.token(DIMS[di], v) for v in vals}:
                    m = 0
                    break
            w = 1
            if c.source_weights:
                w = {self.token("S", s): wt for s, wt in c.source_weights.items()}.get(p.tokens[3], 0)
            for f in self.cfg.agg_features:
                out.append(self.he.encrypt(self.fp.encode(p.feats.get(f, 0)) * w * m))
            out.append(self.he.encrypt((1 - p.delta) * m))
        return tuple(out)

    def close_bucket(self) -> None:
        if not self.bucket_events:
            return
        e, b = self.epoch, self.bucket
        real = [
            _Pending(tuple(self.token(d, v) for d, v in zip(DIMS, (ev.user, ev.res, ev.cat, ev.src))),
                     ev.feats, ev.payload, 0, ev.user)
            for ev in self.bucket_events
        ]
        decoys = self._decoys([p.tokens for p in real], [len(p.payload) for p in real])
        self.stats["real"] += len(real)
        self.stats["decoy"] += len(decoys)
        batch = real + decoys
        self.rng.shuffle(batch)  # pi_b: uniformly random permutation

        if self.cfg.precompute_workers > 0:
            self.precompute(len(batch) * self._he_per_record() - self.he.pool_size())

        t0 = time.perf_counter()
        flagged_refs: dict[str, set] = defaultdict(set)
        for p in batch:
            iota = self.mmr.size
            iv, ct = aead_encrypt(self.keys["P"], bytes([p.delta]) + p.payload, aead_ad(e, b))
            if self.cfg.full_he:
                X = self._full_he_features(p)
            else:
                X = tuple(self.he.encrypt(self.fp.encode(p.feats.get(f, 0))) for f in self.cfg.agg_features)
            X0 = self.he.encrypt(1 - p.delta)
            self.stats["he_enc"] += len(X) + 1
            rec = ProtectedRecord(e, iota, iv, ct, X, X0)
            entry = IndexEntry(p.tokens, b, e, iota)
            self.mmr.append(leaf_data(rec, entry))
            self.epoch_entries[iota] = entry
            if self.cfg.acl:
                self.epoch_X[iota] = (X, X0)
            self.bus.send("ee", "cloud", "record", (rec, entry))
            self.cloud.receive_record(rec, entry)
            if p.user is not None:
                self.user_of[e][p.tokens[0]] = p.user
                flagged_refs[p.user].add(rec.rid)
            else:
                self.decoy_rids.add(rec.rid)
        for T, u in {(p.tokens[0], p.user) for p in real}:
            self.bus.send("ee", "td", "register", (e, T))
            self.td.register(e, T, u)
        self.stats["t_online"] += time.perf_counter() - t0
        if self.cfg.screening:
            self._screen(flagged_refs)
        self.bucket_events = []

    def end_epoch(self) -> tuple[tuple, bytes]:
        self.close_bucket()
        self.bucket = None
        if self.exposure is not None:
            self.exposure.end_epoch()
        t0 = time.perf_counter()
        r_idx = lineage.build_index(self.epoch_entries.values()).root()  # R_e^IDX (eq:index-root)
        self.stats["t_index"] += time.perf_counter() - t0
        cp = (self.epoch, self.mmr.root(), r_idx, self.prev_cp_hash, self.mmr.size)
        sig = self.ka.sign_checkpoint(cp)
        self.bus.send("ka", "ee", "checkpoint_sig", sig)
        self.bus.send("ee", "cloud", "checkpoint", (cp, sig))
        self.cloud.receive_checkpoint(cp, sig)
        self.prev_cp_hash = lineage.checkpoint_hash(cp)
        self.checkpoint = cp
        return cp, sig

    # ================================================================ Phase 3: verify-before-release ACL
    def acl_release(self, q: dict, req: dict) -> dict | None:
        """Algorithm alg:acl on Req_q = (Q_q, candidate set, postings, pi^IDX, A_q, C_Q, C_A).
        On success the EE obtains the KA release and returns Z_q with rho_q; None on failure."""
        hc = HashCounter()
        adds = [0]

        def summer(cts):
            acc = None
            for c in cts:
                acc = c if acc is None else self.he.add(acc, c)
                adds[0] += 1
            return acc if acc is not None else self.he.encrypt(0)

        t0 = time.perf_counter()
        cp = self.checkpoint
        ok = lineage.verify_postings(cp[2], q["tokens"], req["postings"], req["proof"], hc)
        Q = None
        if ok:
            Q = lineage.candidates_from(q["tokens"], req["postings"], cp[4])
            ok = Q == {rid[1] for rid in req["Q"]}
        if ok:
            chi = lineage.c_chi(q, cp, hc)
            cq = lineage.c_q(chi, Q, hc)
            ok = cq == req["C_Q"]
        if ok:
            feat_index = {f: j for j, f in enumerate(self.cfg.agg_features)}
            src = lambda i: self.epoch_entries[i].tokens[3]  # noqa: E731
            aggs, realness = lineage.aggregate(q, Q, self.epoch_X.__getitem__, src, feat_index, self.he, summer)
            ok = (all(int(aggs[f]) == int(req["aggs"][f]) for f in q["feats"])
                  and int(realness) == int(req["realness"]))
        if ok:
            ca = lineage.c_a(cq, q["feats"], aggs, realness, hc)
            ok = ca == req["C_A"]
        rho = lineage.acl_record(chi, cq, ca, hc) if ok else None
        dt = time.perf_counter() - t0
        self.acl_log.append(dict(kind="phase3", qid=q["qid"], epoch=self.epoch, ok=int(ok), seconds=dt,
                                 hashes=hc.count, he_adds=adds[0], q=len(req["Q"]),
                                 postings=sum(len(v) for v in req["postings"].values())))
        if not ok:
            self.stats["acl_reject"] += 1
            # the context keeps its slot with no evidence (fixed feature dimension)
            self.accepted[q["qid"]] = dict(qid=q["qid"], attack=q["attack"], epoch=self.epoch, Q=set(), y={},
                                           phi=(0, 0, 0), rho=None, rejected=True)
            return None
        self.bus.send("ee", "ka", "release_req", (q["qid"], self.epoch, aggs, realness))
        y = self.ka.release(q["qid"], self.epoch, q["policy"], q["threshold"], aggs, realness)
        self.bus.send("ka", "ee", "release", y)
        rids = {(self.epoch, i) for i in Q}
        phi = (len(Q), len({self.epoch_entries[i].tokens[3] for i in Q}), len({self.epoch_entries[i].bucket for i in Q}))
        z = dict(qid=q["qid"], attack=q["attack"], epoch=self.epoch, Q=rids, y=y, phi=phi, rho=rho)
        self.accepted[q["qid"]] = z
        return z

    # ================================================================ Phase 4: graph-lineage verification
    def verify_graph(self, updates: list[tuple], drift: float) -> tuple[list[tuple], float]:
        """Rebuild the attack-relevant contracted neighbourhoods from the accepted Phase 3
        evidence and admit only cloud updates whose C_G matches (journal Phase 4, Step 5)."""
        hc = HashCounter()
        t0 = time.perf_counter()
        Z = list(self.accepted.values())
        profiles = {a: frozenset(self.token("C", c) for c in p.categories) for a, p in self.profiles.items()}
        mine, mu = lineage.contract(Z, lambda rid: self.epoch_entries[rid[1]], profiles, hc)
        expected = {(u[0], u[1]): u for u in mine}
        admitted, bad = [], 0
        for upd in updates:
            ref = expected.pop((upd[0], upd[1]), None)
            if ref is not None and upd[4] == ref[4] and list(upd[2]) == list(ref[2]) and upd[3] == ref[3]:
                admitted.append(upd)
            else:
                bad += 1
        omitted = len(expected)
        my_drift = lineage.drift(mu, self.mu_prev)
        drift_ok = abs(my_drift - drift) <= 1e-12
        self.mu_prev = mu
        dt = time.perf_counter() - t0
        self.acl_log.append(dict(kind="phase4", epoch=self.epoch, ok=int(not bad and not omitted and drift_ok),
                                 seconds=dt, hashes=hc.count, he_adds=0, q=len(updates), rejected=bad,
                                 omitted=omitted))
        self.stats["graph_reject"] += bad
        self.stats["graph_omitted"] += omitted
        self.stats["drift_reject"] += int(not drift_ok)
        return admitted, my_drift

    # ================================================================ Phase 5, Step 6: screening
    def _xi(self, key: bytes) -> float:
        c, m = self.cms_cur.query(key), self.cms_base.query(key)
        return (c - m) ** 2 / max(m, 1.0) if c > m else 0.0

    def _screen(self, refs_by_user: dict[str, set]) -> None:
        """Evaluated at bucket closure, when references exist (Phase 5, Step 6)."""
        self.buckets_seen += 1
        if self.buckets_seen > 6:  # warm-up: baseline needs a few buckets
            pairs = defaultdict(set)
            for ev in self.bucket_events:
                pairs[ev.user].add((ev.res, ev.cat))
            for u, obs in pairs.items():
                psi = max([self._xi(H(u.encode()))] + [self._xi(H(encode(u, r, c))) for r, c in obs])
                if psi >= self.chi2_threshold:
                    d = Descriptor(self.epoch, self.token("U", u), None, psi, None, frozenset(refs_by_user[u]))
                    self.bus.send("ee", "sa", "alert", d)
                    self.sa.receive_alert(d)
        self.cms_base.decay_into(self.cms_cur, math.exp(-self.cfg.screen_decay))
        self.cms_cur.clear()

    # ================================================================ Phase 3/4 inputs
    def make_queries(self) -> list[dict]:
        """Q_q^(e) for every context (eq:protected-query)."""
        qs = []
        for slot, c in enumerate(self.contexts):
            tok = {}
            for dim, vals in zip(DIMS, (c.users, c.resources, c.categories, c.sources)):
                if vals:
                    tok[dim] = frozenset(self.token(dim, v) for v in vals)
            weights = {self.token("S", s): w for s, w in c.source_weights.items()}
            q = dict(qid=c.qid, attack=c.attack, epoch=self.epoch, tokens=tok, feats=c.feats,
                     policy=c.policy, threshold=c.threshold, source_weights=weights, slot=slot)
            qs.append(self.bus.send("ee", "cloud", "query", q))
        return qs

    def graph_profiles(self) -> dict[str, frozenset]:
        """(M_a) tokenized for this epoch; only the graph part of P_a goes to the cloud."""
        out = {a: frozenset(self.token("C", c) for c in p.categories) for a, p in self.profiles.items()}
        return self.bus.send("ee", "cloud", "graph_profiles", out)

    # ================================================================ Phase 5: trusted history
    @staticmethod
    def _dot(w, x) -> float:
        return sum(a * b for a, b in zip(w, x))

    def _hist_score(self, p: AttackProfile, h: list[float]) -> float:
        """r(h): the historical contribution permitted by J_a^hist (all features here).
        Ablation A2 (history=False) scores each epoch alone."""
        if not self.cfg.history:
            return 0.0
        if p.theta_r is not None:
            return self._dot(p.theta_r, h)
        n = len(GRAPH_FEATURES)
        return self._dot(p.theta_g, h[:n]) + self._dot(p.theta_y, h[n:])

    def _prune(self, prov: set, horizon: int) -> set:
        return {rid for rid in prov if rid[0] >= self.epoch - horizon + 1}

    def _lambda(self, p: AttackProfile, drift: float, R: float) -> float:
        """Adaptive decay (eq:adaptive-decay); FixedDecay ablation keeps lambda0."""
        if self.cfg.fixed_decay:
            return p.lambda0
        return min(max(p.lambda0 + p.alpha * drift - p.beta * R, p.lambda_min), p.lambda_max)

    def _explicit_h(self, st: _PairState) -> list[float]:
        """NoContract: rebuild h from the explicit per-epoch history (same values as the
        recursive update, but the state grows with the processed epochs)."""
        dim = len(st.h)
        h = [0.0] * dim
        for _, z, rho in st.zs:
            h = [rho * hv + (1 - rho) * zv for hv, zv in zip(h, z)] if z is not None else [rho * hv for hv in h]
        return h

    def state_size(self) -> int:
        """Floats and references held in trusted historical state (evaluation of NoContract)."""
        n = 0
        for st in self.state.values():
            n += len(st.h) + 1 + len(st.prov) + sum(len(z) + 2 if z is not None else 2 for _, z, _ in st.zs)
        return n

    def phase5(self, updates: list[tuple], drift: float) -> list[Descriptor]:
        if self.cfg.acl:
            updates, drift = self.verify_graph(updates, drift)
        e, alerts, seen = self.epoch, [], set()
        for upd in updates:
            T_u, a, z, refs = upd[:4]
            if T_u in self.dummy[e]:
                self.stats["dummy_updates_discarded"] += 1
                continue
            u = self.user_of[e].get(T_u)
            if u is None:
                continue
            p = self.profiles[a]
            st = self.state.get((u, a)) or _PairState([0.0] * len(z))
            lam = self._lambda(p, drift, st.R)
            rho = math.exp(-lam)
            horizon = math.ceil(math.log(self.cfg.eps_h) / math.log(rho))
            n = len(GRAPH_FEATURES)
            if not self.cfg.contract:
                st.h = self._explicit_h(st)
            S = self._dot(p.theta_g, z[:n]) + self._dot(p.theta_y, z[n:]) + p.theta_h * self._hist_score(p, st.h)
            h_prev = tuple(st.h)
            st.R = _sigmoid(p.kappa * (S - p.Theta))
            st.h = [rho * hv + (1 - rho) * zv for hv, zv in zip(st.h, z)]
            if not self.cfg.contract:
                st.zs.append((e, tuple(z), rho))
            st.prov = self._prune(st.prov | set(refs), horizon)
            if self.cfg.acl:
                st.C_H = lineage.c_h(st.C_H, upd[4], st.h, st.R, st.prov)
            self.state[(u, a)] = st
            seen.add((u, a))
            self.score_log.append((e, u, a, S, tuple(z), h_prev))
            self.horizon_log.append((e, u, a, horizon, lam))
            if S >= p.Theta:
                d = Descriptor(e, T_u, a, S, horizon, frozenset(st.prov), st.C_H if self.cfg.acl else None)
                self.bus.send("ee", "sa", "alert", d)
                self.sa.receive_alert(d)
                alerts.append(d)
        for key in list(self.state):
            if key in seen:
                continue
            st, p = self.state[key], self.profiles[key[1]]
            rho = math.exp(-self._lambda(p, drift, st.R))
            st.h = [rho * hv for hv in st.h]
            if not self.cfg.contract:
                st.zs.append((e, None, rho))
            st.prov = self._prune(st.prov, math.ceil(math.log(self.cfg.eps_h) / math.log(rho)))
            if self.cfg.acl:
                st.C_H = lineage.c_h(st.C_H, lineage.c_inactive(e, key[1]), st.h, st.R, st.prov)
            if self.cfg.contract and math.sqrt(sum(v * v for v in st.h)) < self.cfg.eps_h and not st.prov:
                del self.state[key]  # NoContract keeps its explicit history
        return alerts

    # ================================================================ Phase 6: historical tokens
    def resolve_current(self, epoch: int, token: bytes) -> str | None:
        return self.user_of[epoch].get(token)

    def investigation_queries(self, user: str, attack: str | None, window: range) -> dict[int, dict]:
        """Q_{a,inv}^(tau) per epoch tau in the authorized window (eq:investigation-query)."""
        out = {}
        for tau in window:
            keys = self.bus.send("ka", "ee", "hist_keys", self.ka.epoch_keys(tau))
            tok = {"U": frozenset({self.token("U", user, tau, keys)})}
            if attack is not None:
                for dim, attr in (("R", "resources"), ("C", "categories"), ("S", "sources")):
                    vals = set().union(*(getattr(c, attr) for c in self.contexts if c.attack == attack))
                    if vals:
                        tok[dim] = frozenset(self.token(dim, v, tau, keys) for v in vals)
            out[tau] = self.bus.send("ee", "cloud", "inv_query", tok)
        return out
