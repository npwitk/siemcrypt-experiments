"""Edge Encryptor (EE): the trusted component that sees plaintext.

Phase 1  normalization is done by the loaders; here: tokens (eq:tokens), AES-GCM payloads
         (eq:aes-gcm), HE features (eq:he), realness indicator (eq:realness-indicator),
         frequency-hiding decoy padding (eq:tier, eq:padding-deficit, eq:decoy-count).
Phase 2  index entries (eq:index-entry), MMR commitment (eq:mmr-leaf), checkpoints
         (eq:checkpoint), TD registration (eq:token-mapping).
Phase 3  protected queries (eq:protected-query).
Phase 5  trusted history, adaptive retention, scoring, alerts (eq:adaptive-decay ...
         eq:alert-descriptor); label-free screening (eq:sketch-keys ... eq:unlabeled-alert).
Phase 6  historical token derivation (eq:historical-entity-token, eq:investigation-query).
"""

from __future__ import annotations

import math
import random
import statistics
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from ..bus import Bus
from ..crypto.cms import CountMin
from ..crypto.encoding import FixedPoint, encode
from ..crypto.mmr import MMR
from ..crypto.paillier import Paillier
from ..crypto.primitives import H, aead_encrypt, prf_token
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
        self.prev_root = GENESIS
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

    def ingest(self, ev: Event) -> None:
        b = int(ev.ts // self.cfg.bucket_len)
        if self.bucket is not None and b != self.bucket:
            self.close_bucket()
        self.bucket = b
        self.bucket_events.append(ev)
        if self.cfg.screening:
            self.cms_cur.update(H(ev.user.encode()))
            self.cms_cur.update(H(encode(ev.user, ev.res, ev.cat)))

    def _decoys(self, real_tokens: list[tuple], real_lengths: list[int]) -> list[_Pending]:
        """Frequency-hiding padding for one bucket (Phase 1, Step 5)."""
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
            self.precompute(len(batch) * (len(self.cfg.agg_features) + 1) - self.he.pool_size())

        t0 = time.perf_counter()
        flagged_refs: dict[str, set] = defaultdict(set)
        for p in batch:
            iota = self.mmr.size
            iv, ct = aead_encrypt(self.keys["P"], bytes([p.delta]) + p.payload, aead_ad(e, b))
            X = tuple(self.he.encrypt(self.fp.encode(p.feats.get(f, 0))) for f in self.cfg.agg_features)
            X0 = self.he.encrypt(1 - p.delta)
            self.stats["he_enc"] += len(X) + 1
            rec = ProtectedRecord(e, iota, iv, ct, X, X0)
            entry = IndexEntry(p.tokens, b, e, iota)
            self.mmr.append(leaf_data(rec, entry))
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
        cp = (self.epoch, self.mmr.root(), self.prev_root, self.mmr.size)
        sig = self.ka.sign_checkpoint(cp)
        self.bus.send("ka", "ee", "checkpoint_sig", sig)
        self.bus.send("ee", "cloud", "checkpoint", (cp, sig))
        self.cloud.receive_checkpoint(cp, sig)
        self.prev_root = cp[1]
        return cp, sig

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
        for c in self.contexts:
            tok = {}
            for dim, vals in zip(DIMS, (c.users, c.resources, c.categories, c.sources)):
                if vals:
                    tok[dim] = frozenset(self.token(dim, v) for v in vals)
            weights = {self.token("S", s): w for s, w in c.source_weights.items()}
            q = dict(qid=c.qid, attack=c.attack, epoch=self.epoch, tokens=tok, feats=c.feats,
                     policy=c.policy, threshold=c.threshold, source_weights=weights)
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

    def phase5(self, updates: list[tuple], drift: float) -> list[Descriptor]:
        e, alerts, seen = self.epoch, [], set()
        for T_u, a, z, refs in updates:
            if T_u in self.dummy[e]:
                self.stats["dummy_updates_discarded"] += 1
                continue
            u = self.user_of[e].get(T_u)
            if u is None:
                continue
            p = self.profiles[a]
            st = self.state.get((u, a)) or _PairState([0.0] * len(z))
            lam = min(max(p.lambda0 + p.alpha * drift - p.beta * st.R, p.lambda_min), p.lambda_max)
            rho = math.exp(-lam)
            horizon = math.ceil(math.log(self.cfg.eps_h) / math.log(rho))
            n = len(GRAPH_FEATURES)
            S = self._dot(p.theta_g, z[:n]) + self._dot(p.theta_y, z[n:]) + p.theta_h * self._hist_score(p, st.h)
            h_prev = tuple(st.h)
            st.R = 1.0 / (1.0 + math.exp(-p.kappa * (S - p.Theta)))
            st.h = [rho * hv + (1 - rho) * zv for hv, zv in zip(st.h, z)]
            st.prov = self._prune(st.prov | set(refs), horizon)
            self.state[(u, a)] = st
            seen.add((u, a))
            self.score_log.append((e, u, a, S, tuple(z), h_prev))
            if S >= p.Theta:
                d = Descriptor(e, T_u, a, S, horizon, frozenset(st.prov))
                self.bus.send("ee", "sa", "alert", d)
                self.sa.receive_alert(d)
                alerts.append(d)
        for key in list(self.state):
            if key in seen:
                continue
            st, p = self.state[key], self.profiles[key[1]]
            lam = min(max(p.lambda0 + p.alpha * drift - p.beta * st.R, p.lambda_min), p.lambda_max)
            rho = math.exp(-lam)
            st.h = [rho * hv for hv in st.h]
            st.prov = self._prune(st.prov, math.ceil(math.log(self.cfg.eps_h) / math.log(rho)))
            if math.sqrt(sum(v * v for v in st.h)) < self.cfg.eps_h and not st.prov:
                del self.state[key]
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
