"""Leakage-Adaptive Pattern Hiding (journal Phase 1, Step 4; eq:leakage-score ..
eq:adaptive-deficit).

Exposure score of an entity or resource value v in bucket b (computed by the EE on
plaintext, never sent to the cloud):

  L_{d,b}(v) = w_f * L_freq(v) + w_s * L_str(v) + w_h * L_stab(v),   each term in [0, 1]

The journal names the three terms but does not define them; this prototype uses
  L_freq  log(1 + c_b(v)) / log(1 + max_v' c_b(v'))     heavy hitters are what rank-matching
                                                       frequency analysis recovers first
  L_str   share of v's relations whose counterpart is related to v alone in the bucket
                                                       (a unique entity-resource edge)
  L_stab  share of the last H epochs in which v occurred   (persistent values are linkable)
(docs/decisions.md, D22). Tiers: gamma(v) = 1 if L < theta_1, gamma_1 if L < theta_2,
gamma_2 otherwise (eq:adaptive-gamma); deficit zeta = Tier_gamma(c) - c (eq:adaptive-deficit).

Decoys reuse real values: entity and resource deficits are filled jointly, preferring an
existing relation of the bucket whose both ends still have a deficit, otherwise drawing the
counterpart from the bucket's empirical conditional relation distribution. The category and
source of a decoy are drawn from the real events of the chosen relation.

Scope (cfg.laph_scope). "bucket" is the journal draft: scores, tiers and deficits per bucket.
Because the cloud also sees epoch totals and padding only adds records, per-bucket tiers
leave the epoch-level frequency ranking intact (results/laptop-journal-2026-10-22). "epoch"
(D26): the EE holds the epoch's events until the epoch closes (Phases 3-5 run then anyway),
scores and tiers every value on its epoch count, and spreads each decoy over the buckets in
which its relation really occurred, so equal tier targets give equal epoch totals.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict, deque

from .model import Config, Event


def tier(c: int, gamma: float) -> int:
    """Tier_gamma(c) = min{ceil(gamma^k) : ceil(gamma^k) >= c}; Tier_1(c) = c (eq:adaptive-tier)."""
    if c < 1:
        raise ValueError("tier defined for c >= 1")
    if gamma <= 1:
        return c
    k, v = 0, 1
    while v < c:
        k += 1
        v = math.ceil(gamma**k)
    return v


class ExposureTracker:
    """EE-side state of LAPH: bounded history of the values seen in recent epochs."""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.history: deque[set] = deque(maxlen=cfg.laph_hist)
        self.cur: set = set()

    def scores(self, events: list[Event]) -> dict[tuple[str, str], float]:
        """L_{d,b}(v) for every entity (d = U) and resource (d = R) value of one bucket."""
        w_f, w_s, w_h = self.cfg.laph_w
        rel = Counter((ev.user, ev.res) for ev in events)
        nb = {"U": defaultdict(set), "R": defaultdict(set)}
        for u, r in rel:
            nb["U"][u].add(r)
            nb["R"][r].add(u)
        out = {}
        for dim, attr, other in (("U", "user", "R"), ("R", "res", "U")):
            cnt = Counter(getattr(ev, attr) for ev in events)
            top = math.log1p(max(cnt.values()))
            for v, c in cnt.items():
                f = math.log1p(c) / top if top else 0.0
                s = sum(1 for x in nb[dim][v] if len(nb[other][x]) == 1) / len(nb[dim][v])
                h = sum(1 for past in self.history if (dim, v) in past) / self.cfg.laph_hist
                out[(dim, v)] = w_f * f + w_s * s + w_h * h
            self.cur.update((dim, v) for v in cnt)
        return out

    def end_epoch(self) -> None:
        self.history.append(self.cur)
        self.cur = set()

    def gamma(self, score: float) -> float:
        t1, t2 = self.cfg.laph_theta
        g1, g2 = self.cfg.laph_gamma
        return 1.0 if score < t1 else (g1 if score < t2 else g2)


def plan_decoys(events: list[Event], gamma_of: dict[tuple[str, str], float], rng) -> list[tuple]:
    """Decoy (user, res, cat, src, ts, payload length) tuples that fill the deficits of gamma_of
    over `events` (one bucket, or a whole epoch); everything but the identities is copied from a
    real event of the relation, so the ciphertext length matches real records of that kind."""
    cnt = {"U": Counter(ev.user for ev in events), "R": Counter(ev.res for ev in events)}
    zeta = {(d, v): tier(c, gamma_of.get((d, v), 1.0)) - c for d in cnt for v, c in cnt[d].items()}
    rel = Counter((ev.user, ev.res) for ev in events)
    by_u, by_r = defaultdict(Counter), defaultdict(Counter)
    for (u, r), n in rel.items():
        by_u[u][r] += n
        by_r[r][u] += n
    cs = defaultdict(list)
    for ev in events:
        cs[(ev.user, ev.res)].append((ev.cat, ev.src, ev.ts, len(ev.payload)))

    def draw(counter: Counter):
        keys = sorted(counter)
        return rng.choices(keys, [counter[k] for k in keys])[0]

    pairs = []
    users = sorted(u for u in cnt["U"] if zeta[("U", u)] > 0)
    rng.shuffle(users)
    for u in users:
        while zeta[("U", u)] > 0:
            both = Counter({r: n for r, n in by_u[u].items() if zeta[("R", r)] > 0})
            r = draw(both if both else by_u[u])
            zeta[("U", u)] -= 1
            if zeta[("R", r)] > 0:
                zeta[("R", r)] -= 1
            pairs.append((u, r))
    res = sorted(r for r in cnt["R"] if zeta[("R", r)] > 0)
    rng.shuffle(res)
    for r in res:
        # entity tiers stay exact: the counterpart must be an unpadded entity of the relation;
        # without one the resource deficit is left open (resource tiers are best effort,
        # identities are what the cloud wants)
        free = Counter({u: n for u, n in by_r[r].items() if gamma_of.get(("U", u), 1.0) <= 1})
        while free and zeta[("R", r)] > 0:
            pairs.append((draw(free), r))
            zeta[("R", r)] -= 1
    return [(u, r, *rng.choice(cs[(u, r)])) for u, r in pairs]


def exposure_by_epoch(events: list[Event], cfg: Config) -> dict[tuple[int, str, str], float]:
    """Evaluation helper: max_b L_{d,b}(v) per (epoch, dim, value), as the EE computes it."""
    tr = ExposureTracker(cfg)
    out: dict[tuple[int, str, str], float] = {}
    by_eb = defaultdict(list)
    for ev in events:
        by_eb[(int(ev.ts // cfg.epoch_len) + 1, int(ev.ts // cfg.bucket_len))].append(ev)
    cur = None
    for (e, b) in sorted(by_eb):
        if cur is not None and e != cur:
            tr.end_epoch()
        cur = e
        for (d, v), L in tr.scores(by_eb[(e, b)]).items():
            out[(e, d, v)] = max(out.get((e, d, v), 0.0), L)
    return out
