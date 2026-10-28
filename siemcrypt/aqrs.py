"""Adaptive Query and Result Shaping (journal v2, Phase 3, Steps 1-2; eq:aqrs-risk ..
eq:dispatch-slot).

EE-side state and decisions only; the cloud sees the cohort of protected queries.

A hunting query is a plaintext spec (d, v, cats): records whose dimension d (U or R) equals v,
optionally restricted to categories cats. Its coarse structure is sigma = (d, cats); a cover
query keeps sigma and replaces v by another value of the epoch.

  risk     R_q = a_r * rep + a_v * vol + a_t * time                       eq:aqrs-risk
           rep  repetitions of q so far (this epoch, or the previous epoch with cfg.aqrs_sticky),
                (n - 1) / (r_max - 1) capped at 1
           vol  1 - min(1, |compatible covers| / (2 (k_2 - 1)))   rare volume tiers are distinctive
           time share of the last H epochs in which q was issued    (recurring queries are predictable)
  profile  pi_0 (k = 1) if R < theta_1, pi_1 (k_1) if R < theta_2, else pi_2 (k_2) + dispatch slot
  covers   Compat: same sigma and same volume tier nu(n) = floor(log2 n) (n = 0: its own tier);
           "nearest" takes the k - 1 covers minimizing |n - n'| (eq:cover-distance, beta_v = 1),
           "random" draws them uniformly from the compatible pool; "near-random" (D28) draws k - 1 of the
           2 (k - 1) nearest in log volume, and with cfg.aqrs_compat = "sigma" the tier constraint
           is dropped, so a query in a sparse tier still gets k - 1 covers
  cohort   stable for the epoch per real query (extended, never reshuffled, if its profile
           grows); cfg.aqrs_dynamic redraws the covers on every issue (Dynamic-Cover ablation)

cfg.aqrs: "direct" (no cohort), "fixed" (k = cfg.aqrs_fixed_k for every query), "adaptive".
cfg.aqrs_sticky (D28): the profile and cohort of a query are fixed at its first issue in the
epoch from trusted history only, so a later repetition cannot escalate a query the cloud has
already seen alone.
"""

from __future__ import annotations

import math
from collections import Counter, deque
from dataclasses import dataclass

from .model import Config


@dataclass(frozen=True)
class Spec:
    dim: str                     # "U" or "R"
    value: str
    cats: frozenset | None = None

    @property
    def sigma(self) -> tuple:
        return (self.dim, self.cats)


def vtier(n: int) -> int:
    """nu(n): the expected retrieval-volume tier."""
    return -1 if n <= 0 else int(math.log2(n))


class AQRS:
    def __init__(self, cfg: Config, rng):
        self.cfg, self.rng = cfg, rng
        self.history: deque[Counter] = deque(maxlen=cfg.aqrs_hist)  # issues per spec, past epochs
        self.cur = Counter()
        self.cohorts: dict[Spec, list[Spec]] = {}
        self.profile_of: dict[Spec, int] = {}
        self.tuples = Counter()
        self._vol: dict[tuple, Counter] = {}
        self._domain: dict[str, set] = {}

    # ---------------------------------------------------------------- epoch state
    def start_epoch(self, tuples: Counter) -> None:
        """tuples: plaintext (u, r, c, s) -> count of the epoch's real events (EE-side)."""
        self.tuples = tuples
        self._vol, self.cohorts, self.profile_of = {}, {}, {}
        self._domain = {"U": {t[0] for t in tuples}, "R": {t[1] for t in tuples}}

    def end_epoch(self) -> None:
        self.history.append(self.cur)
        self.cur = Counter()

    def volumes(self, sigma: tuple) -> Counter:
        if sigma not in self._vol:
            d, cats = sigma
            k = 0 if d == "U" else 1
            vol = Counter({v: 0 for v in self._domain[d]})
            for t, n in self.tuples.items():
                if cats is None or t[2] in cats:
                    vol[t[k]] += n
            self._vol[sigma] = vol
        return self._vol[sigma]

    def pool(self, s: Spec) -> list[str]:
        """Compatible covers: same sigma and volume tier (eq:cover-compatibility)."""
        vol = self.volumes(s.sigma)
        tv = vtier(vol[s.value])
        return sorted(v for v, n in vol.items() if v != s.value and vtier(n) == tv)

    def _candidates(self, s: Spec) -> list[str]:
        if self.cfg.aqrs_compat == "tier":
            return self.pool(s)
        vol = self.volumes(s.sigma)  # "sigma": any value of the same structure with volume > 0 iff s has
        return sorted(v for v, n in vol.items() if v != s.value and (n > 0) == (vol[s.value] > 0))

    # ---------------------------------------------------------------- Step 1: risk and profile
    def risk(self, s: Spec, n_issue: int) -> float:
        a_r, a_v, a_t = self.cfg.aqrs_alpha
        k2 = self.cfg.aqrs_k[2]
        rmax = self.cfg.aqrs_rmax
        rep = min(1.0, (n_issue - 1) / (rmax - 1))
        vol = 1.0 - min(1.0, len(self.pool(s)) / (2 * (k2 - 1)))
        past = sum(1 for h in self.history if h[s] > 0)
        time = past / self.cfg.aqrs_hist
        return a_r * rep + a_v * vol + a_t * time

    def profile(self, r: float) -> int:
        t1, t2 = self.cfg.aqrs_theta
        return 0 if r < t1 else (1 if r < t2 else 2)

    def k_of(self, pi: int) -> int:
        mode = self.cfg.aqrs
        if mode == "direct":
            return 1
        if mode == "fixed":
            return self.cfg.aqrs_fixed_k
        return self.cfg.aqrs_k[pi]

    # ---------------------------------------------------------------- Step 2: cohort
    def _covers(self, s: Spec, n: int, exclude: set) -> list[Spec]:
        if n <= 0:
            return []
        cand = [v for v in self._candidates(s) if v not in exclude]
        vol = self.volumes(s.sigma)
        if self.cfg.aqrs_select in ("nearest", "near-random") and not self.cfg.aqrs_dynamic:
            self.rng.shuffle(cand)  # random tie-break among equal distances
            cand.sort(key=lambda v: abs(math.log1p(vol[v]) - math.log1p(vol[s.value])))
            if self.cfg.aqrs_select == "nearest":
                pick = cand[:n]
            else:  # D28: n of the 2n nearest at random, so the real query is not the centre
                pick = self.rng.sample(cand[:2 * n], min(n, len(cand[:2 * n])))
        else:
            pick = self.rng.sample(cand, min(n, len(cand)))
        return [Spec(s.dim, v, s.cats) for v in pick]

    def issue(self, s: Spec) -> tuple[list[Spec], dict]:
        """Cohort for one issue of s (real query first) and the EE-side record of the decision."""
        self.cur[s] += 1
        n_issue = self.cur[s]
        if self.cfg.aqrs_sticky:
            # profile from trusted history only, fixed at the first issue of the epoch
            if s not in self.profile_of:
                prev = self.history[-1][s] if self.history else 0
                self.profile_of[s] = self.profile(self.risk(s, max(1, prev)))
            pi = self.profile_of[s]
            r = None
        else:
            r = self.risk(s, n_issue)
            pi = self.profile(r)
        k = self.k_of(pi)
        if self.cfg.aqrs_dynamic:
            members = [s] + self._covers(s, k - 1, {s.value})
        else:
            members = self.cohorts.get(s, [s])
            if len(members) < k:  # extend, never reshuffle
                members = members + self._covers(s, k - len(members), {m.value for m in members})
            self.cohorts[s] = members
        disp = self.cfg.aqrs_slot if pi == 2 and self.cfg.aqrs != "direct" else 0
        cls = self.profile(self.risk(s, n_issue))  # exposure class for reporting (same in every mode)
        return members, dict(spec=s, n_issue=n_issue, risk=r, pi=pi, cls=cls, k=k, k_eff=len(members), slot=disp)
