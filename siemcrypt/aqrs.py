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

"partition" (D29): the values of each dimension are ranked by their real epoch volume and cut
into consecutive groups of k_max (a short tail joins the last group), each group into consecutive
sub-groups of the smaller cohort size. A query's cohort is its whole (sub-)group, so the cohort is
a function of the group, not of the real query: the real member is not the centre or the extreme
of its covers by construction. Groups ignore the category filter (a value has one group for every
sigma, so cohorts of one value under different filters do not intersect to it). With
padding="cohort" the EE pads every member of a group to the group maximum (siemcrypt/laph.py,
plan_cohort), so the cloud sees equal volumes inside a cohort.

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
        self.groups: dict[tuple[str, str], tuple[tuple, tuple]] = {}  # (dim, v) -> (group, sub-group)
        self._kept = False
        self.known: deque[set] = deque(maxlen=cfg.aqrs_hist)  # (dim, v) seen in recent epochs

    # ---------------------------------------------------------------- epoch state
    def start_epoch(self, tuples: Counter) -> None:
        """tuples: plaintext (u, r, c, s) -> count of the epoch's cloud-visible records (EE-side)."""
        self.tuples = tuples
        self._vol, self.cohorts, self.profile_of = {}, {}, {}
        self._domain = {"U": {t[0] for t in tuples}, "R": {t[1] for t in tuples}}
        if self.cfg.aqrs_select == "partition" and not self._kept:
            self.partition(tuples)
        self._kept = False

    def sizes(self) -> tuple[int, int]:
        """(k_max, k_sub) of the partition."""
        if self.cfg.aqrs == "fixed":
            return self.cfg.aqrs_fixed_k, self.cfg.aqrs_fixed_k
        ks = sorted({k for k in self.cfg.aqrs_k if k > 1}) or [1]
        return ks[-1], ks[0]

    @staticmethod
    def _chunks(seq: list, k: int) -> list[list]:
        out = [seq[i:i + k] for i in range(0, len(seq), k)]
        if len(out) > 1 and len(out[-1]) < k:
            tail = out.pop()
            out[-1] = out[-1] + tail
        return out

    def partition(self, real: Counter, keep: bool = False) -> dict[str, list[tuple]]:
        """Groups of consecutive volume ranks per dimension (D29), from the real epoch counts;
        keep=True: computed before padding, kept by the next start_epoch."""
        kmax, ksub = self.sizes()
        self.groups, out = {}, {}
        cur = {("U", t[0]) for t in real} | {("R", t[1]) for t in real}
        past = set().union(*self.known) if self.known else set()
        self.known.append(cur)
        for d, i in (("U", 0), ("R", 1)):
            # values of recent epochs with no record now stay in the domain (volume 0), so a hunt
            # for a value that went quiet still gets a cohort
            vol = Counter({v: 0 for dd, v in past if dd == d})
            for t, n in real.items():
                vol[t[i]] += n
            vals = sorted(vol)
            self.rng.shuffle(vals)  # random order among equal volumes
            vals.sort(key=lambda v: -vol[v])
            out[d] = []
            for g in self._chunks(vals, kmax):
                g = tuple(g)
                out[d].append(g)
                for sub in self._chunks(list(g), ksub):
                    for v in sub:
                        self.groups[(d, v)] = (g, tuple(sub))
        self._kept = keep
        return out

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
        if self.cfg.aqrs_select == "partition":
            g, sub = self.groups.get((s.dim, s.value), ((s.value,), (s.value,)))
            grp = sub if len(exclude | {s.value}) + n <= len(sub) else g  # target size k
            return [Spec(s.dim, v, s.cats) for v in grp if v not in exclude and v != s.value]
        cand = [v for v in self._candidates(s) if v not in exclude]
        vol = self.volumes(s.sigma)
        if self.cfg.aqrs_select in ("nearest", "near-random", "equal-first") and not self.cfg.aqrs_dynamic:
            self.rng.shuffle(cand)  # random tie-break among equal distances
            cand.sort(key=lambda v: abs(math.log1p(vol[v]) - math.log1p(vol[s.value])))
            if self.cfg.aqrs_select == "nearest":
                pick = cand[:n]
            elif self.cfg.aqrs_select == "equal-first":
                # D28 with padding: values padded to the same cloud-visible volume first (they are
                # indistinguishable by volume), the rest near-random as below
                same = [v for v in cand if vol[v] == vol[s.value]]
                pick = self.rng.sample(same, min(n, len(same)))
                rest = [v for v in cand if v not in set(pick)][:2 * (n - len(pick))]
                pick += self.rng.sample(rest, min(n - len(pick), len(rest)))
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
