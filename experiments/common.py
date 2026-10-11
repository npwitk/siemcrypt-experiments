"""Shared helpers for the experiment scripts: systems under test, threshold calibration,
incident-level detection scoring, the Wazuh-style rule emulation (B1-emu), and output.

Systems (DS2, Tables "Systems compared" and "Ablations")
  S    SIEMCrypt with the default configuration (no decoys, gamma = 1)
  SD   SIEMCrypt with decoy padding (gamma = 2), the optional frequency-hiding mode
  B2   plaintext twin: same correlation logic, no padding, no minimum support
  A2   one-epoch window (no trusted history)
  A3   no label-free screening
  A4   persistent tokens (no epoch rotation)
  A5   no minimum support (k_min = 0)
B1-emu is NOT Wazuh: it applies Wazuh's frequency/timeframe rule semantics to the same
normalized events, so it can run next to the prototype. The real Wazuh run is on the VM.
"""

from __future__ import annotations

import csv
import json
import math
import statistics
from bisect import bisect_left
from collections import defaultdict
from dataclasses import asdict, dataclass, replace
from pathlib import Path

from siemcrypt.data.synth import GroundTruth, SynthConfig, default_profiles_and_contexts, generate
from siemcrypt.model import AttackProfile, Config, Event
from siemcrypt.system import SIEMCrypt

RESULTS = Path(__file__).resolve().parents[1] / "results"

BASE = Config(paillier_bits=512, agg_features=("count", "bytes"), seed=1, precompute_workers=0)

VARIANTS = {
    "S": {},
    "SD": {"gamma": 2.0},
    "B2": {"gamma": 1.0, "k_min": 0},
    "A2": {"history": False},
    "A3": {"screening": False},
    "A4": {"persistent_tokens": True},
    "A5": {"k_min": 0},
}


def config(variant: str, **overrides) -> Config:
    return replace(BASE, **{**VARIANTS[variant], **overrides})


# ============================================================================ running
def run(cfg: Config, events: list[Event], profiles=None, contexts=None) -> SIEMCrypt:
    if profiles is None or contexts is None:
        p0, c0 = default_profiles_and_contexts()
        profiles, contexts = profiles or p0, contexts or c0
    s = SIEMCrypt(cfg, profiles, contexts)
    s.run(events)
    return s


def benign(sc: SynthConfig) -> SynthConfig:
    return replace(sc, n_brute_force=0, n_low_and_slow=0, n_exfil=0, n_coordinated=0)


def remap_truth(truth: list[GroundTruth], gen_epoch_len: float, sys_epoch_len: float) -> list[GroundTruth]:
    """Express attack spans (generator epochs, 1-based) in system epochs of another length."""
    if gen_epoch_len == sys_epoch_len:
        return truth
    out = []
    for gt in truth:
        eps = set()
        for e in gt.epochs:
            lo, hi = (e - 1) * gen_epoch_len, e * gen_epoch_len
            eps.update(range(int(lo // sys_epoch_len) + 1, int((hi - 1e-9) // sys_epoch_len) + 2))
        out.append(replace(gt, epochs=sorted(eps)))
    return out


def system_epochs(sc: SynthConfig, cfg: Config) -> int:
    return math.ceil(sc.epochs * sc.epoch_len / cfg.epoch_len)


def fit_weights(score_logs: list[tuple[list, set]], profiles: list[AttackProfile],
                history: bool) -> list[AttackProfile]:
    """Logistic regression of theta_g, theta_y and r(h) = theta_r . h per profile.
    score_logs: (EE score_log, positive (user, class, epoch) set) per development run.

    Real-data features span several orders of magnitude (event counts in the thousands),
    so they are standardized for fitting and the coefficients mapped back to raw units
    (w_raw = w_std / sd). The score stays the linear function of the paper; the intercept
    and centering only shift S, which the calibrated threshold Theta absorbs."""
    import numpy as np
    from sklearn.linear_model import LogisticRegression

    out = []
    for p in profiles:
        rows = [(z, h, (u, a, e) in pos) for log, pos in score_logs
                for (e, u, a, _, z, h) in log if a == p.name]
        y = [lab for *_, lab in rows]
        if len(set(y)) < 2:
            out.append(p)
            continue
        X = np.array([list(z) + (list(h) if history else []) for z, h, _ in rows], float)
        sd = X.std(axis=0)
        sd[sd == 0] = 1.0
        m = LogisticRegression(C=1.0, class_weight="balanced", max_iter=10000).fit((X - X.mean(axis=0)) / sd, y)
        w = [float(v) for v in m.coef_[0] / sd]
        nz, ng = len(rows[0][0]), len(p.theta_g)
        out.append(replace(p, theta_g=tuple(w[:ng]), theta_y=tuple(w[ng:nz]), theta_h=1.0,
                           theta_r=tuple(w[nz:]) if history else None))
    return out


def theta_for_budget(score_logs: list[tuple[list, set]], profiles: list[AttackProfile],
                     allowed: int) -> list[AttackProfile]:
    """Theta_a such that at most `allowed` benign (entity, epoch) scores reach it, pooled over
    development runs. score_logs: (EE score_log, set of excluded attacker entities)."""
    out = []
    for p in profiles:
        scores = sorted((S for log, bad in score_logs for (_, u, a, S, *_) in log
                         if a == p.name and u not in bad), reverse=True)
        theta = scores[allowed] + 1e-6 if len(scores) > allowed else (scores[-1] if scores else p.Theta)
        out.append(replace(p, Theta=theta))
    return out


def learn_weights(cfg: Config, dev: SynthConfig) -> list[AttackProfile]:
    """Fit theta_g, theta_y and r(h) = theta_r . h per attack profile by logistic regression
    on a development stream with injected attacks (labels from its ground truth). With
    history disabled (A2) only the current-epoch features are used."""
    from sklearn.linear_model import LogisticRegression

    profiles, contexts = default_profiles_and_contexts()
    events, truth = generate(dev)
    truth = remap_truth(truth, dev.epoch_len, cfg.epoch_len)
    s = run(cfg, events, profiles, contexts)
    pos = {(gt.user, gt.attack_class, e) for gt in truth for e in gt.epochs}
    out = []
    for p in profiles:
        rows = [(z, h, (u, a, e) in pos) for (e, u, a, _, z, h) in s.ee.score_log if a == p.name]
        X = [list(z) + (list(h) if cfg.history else []) for z, h, _ in rows]
        y = [lab for *_, lab in rows]
        if len(set(y)) < 2:
            out.append(p)
            continue
        m = LogisticRegression(C=1.0, class_weight="balanced", max_iter=10000).fit(X, y)
        w = [float(v) for v in m.coef_[0]]
        nz, ng = len(rows[0][0]), len(p.theta_g)
        out.append(replace(p, theta_g=tuple(w[:ng]), theta_y=tuple(w[ng:nz]), theta_h=1.0,
                           theta_r=tuple(w[nz:]) if cfg.history else None))
    return out


def calibrate(cfg: Config, dev: SynthConfig, target_fpr: float, passes: int = 2,
              profiles: list[AttackProfile] | None = None) -> list[AttackProfile]:
    """Set Theta_a so that at most target_fpr of benign (entity, epoch) pairs alert for a,
    on an attack-free development stream. Theta feeds back into the decay through the
    risk state, so the calibration is repeated (`passes`)."""
    p0, contexts = default_profiles_and_contexts()
    profiles = profiles or p0
    events, _ = generate(benign(dev))
    opportunities = dev.n_users * system_epochs(dev, cfg)
    allowed = math.floor(target_fpr * opportunities)
    for _ in range(passes):
        s = run(cfg, events, profiles, contexts)
        new = []
        for p in profiles:
            scores = sorted((S for (_, _, a, S, *_) in s.ee.score_log if a == p.name), reverse=True)
            theta = scores[allowed] + 1e-6 if len(scores) > allowed else (scores[-1] if scores else p.Theta)
            new.append(replace(p, Theta=theta))
        profiles = new
    return profiles


# ============================================================================ scoring
@dataclass
class ClassScore:
    attack_class: str
    incidents: int
    detected: int
    alerted_pairs: int
    true_pairs: int
    precision: float
    recall: float
    f1: float
    mean_delay: float | None


def _f1(p: float, r: float) -> float:
    return 2 * p * r / (p + r) if p + r else 0.0


def score_alerts(alerts: set[tuple[str, str, int]], truth: list[GroundTruth],
                 classes: list[str]) -> tuple[dict[str, ClassScore], dict[str, tuple[int, int | None]]]:
    """Incident-level scoring.

    alerts: (user, class, epoch). An incident (user, class) is detected when an alert names
    the user and class in an epoch of the attack's span. Precision is over distinct alerted
    (user, class) pairs; a pair is true if some incident of that pair was detected.
    Returns per-class scores and, per attack id, (detected, delay in epochs).
    """
    by_pair = defaultdict(set)
    for u, a, e in alerts:
        by_pair[(u, a)].add(e)
    per_incident = {}
    true_pairs = set()
    for gt in truth:
        eps = sorted(by_pair.get((gt.user, gt.attack_class), set()) & set(gt.epochs))
        per_incident[gt.attack_id] = (int(bool(eps)), (eps[0] - min(gt.epochs)) if eps else None)
        if eps:
            true_pairs.add((gt.user, gt.attack_class))
    out = {}
    for c in classes:
        inc = [gt for gt in truth if gt.attack_class == c]
        det = sum(per_incident[gt.attack_id][0] for gt in inc)
        pairs = {k for k in by_pair if k[1] == c}
        tp = len(pairs & true_pairs)
        prec = tp / len(pairs) if pairs else (1.0 if not inc else 0.0)
        rec = det / len(inc) if inc else float("nan")
        delays = [per_incident[gt.attack_id][1] for gt in inc if per_incident[gt.attack_id][0]]
        out[c] = ClassScore(c, len(inc), det, len(pairs), tp, prec, rec,
                            _f1(prec, rec) if inc else float("nan"),
                            statistics.mean(delays) if delays else None)
    return out, per_incident


def siemcrypt_alerts(s: SIEMCrypt) -> tuple[set, set]:
    """Classified alerts (user, class, epoch) and unclassified screening alerts (user, epoch).
    The evaluator resolves tokens through the EE's own mapping (ground truth access)."""
    cls, unl = set(), set()
    for d in s.sa.alerts:
        u = s.ee.resolve_current(d.epoch, d.token)
        (cls.add((u, d.attack, d.epoch)) if d.attack else unl.add((u, d.epoch)))
    return cls, unl


def siemcrypt_scores(s: SIEMCrypt) -> dict[tuple[str, str, int], float]:
    """Score S_{u,a}^(e) of every evaluated (user, class, epoch) (evaluation only)."""
    return {(u, a, e): S for (e, u, a, S, *_) in s.ee.score_log}


def threshold_free(scores: dict[tuple[str, str, int], float], truth: list[GroundTruth],
                   classes: list[str], fp_budget: int = 2) -> dict[str, dict]:
    """Operating-point-free comparison, per class.

    auc        ROC AUC of scores over evaluated (user, epoch) pairs; positives are the
               epochs inside an attack span of that class
    recall@fp  incident recall at the threshold that lets exactly `fp_budget` benign
               users alert (their maximum score over all epochs is above it)
    Pairs a system never scores (no relevant events) count as score -inf.
    """
    from sklearn.metrics import roc_auc_score

    out = {}
    for c in classes:
        inc = [gt for gt in truth if gt.attack_class == c]
        attackers = {gt.user for gt in inc}
        pos = {(gt.user, e) for gt in inc for e in gt.epochs}
        rows = [(v, (u, e) in pos) for (u, a, e), v in scores.items() if a == c]
        y = [lab for _, lab in rows]
        auc = roc_auc_score(y, [v for v, _ in rows]) if len(set(y)) == 2 else float("nan")
        ben = defaultdict(lambda: -math.inf)
        for (u, a, e), v in scores.items():
            if a == c and u not in attackers:
                ben[u] = max(ben[u], v)
        ranked = sorted(ben.values(), reverse=True)
        thr = ranked[fp_budget] if len(ranked) > fp_budget else -math.inf
        hit = [any(scores.get((gt.user, c, e), -math.inf) > thr for e in gt.epochs) for gt in inc]
        out[c] = dict(auc=auc, recall_at_fp=sum(hit) / len(hit) if hit else float("nan"))
    return out


# ============================================================================ B1-emu
@dataclass(frozen=True)
class FreqRule:
    """Wazuh frequency rule: `frequency` matching events of one user within `timeframe` s."""

    attack_class: str
    categories: frozenset[str]
    frequency: int
    timeframe: float


WAZUH_DEFAULT = [
    # sshd rule 5720 style: 8 authentication failures within 120 s
    FreqRule("cred_access", frozenset({"auth_fail"}), 8, 120.0),
    FreqRule("exfil", frozenset({"data_transfer"}), 8, 120.0),
    FreqRule("multi_source", frozenset({"conn_denied", "ids_alert"}), 8, 120.0),
]


def rule_alerts(events: list[Event], rules: list[FreqRule], epoch_len: float) -> set[tuple[str, str, int]]:
    out = set()
    for rule in rules:
        times = defaultdict(list)
        for ev in events:
            if ev.cat in rule.categories:
                times[ev.user].append(ev.ts)
        for u, ts in times.items():
            ts.sort()
            for i, t in enumerate(ts):
                j = bisect_left(ts, t - rule.timeframe)
                if i - j + 1 >= rule.frequency:
                    out.add((u, rule.attack_class, int(t // epoch_len) + 1))
    return out


def rule_scores(events: list[Event], rules: list[FreqRule], epoch_len: float) -> dict[tuple[str, str, int], float]:
    """Threshold-free score of a frequency rule: the largest number of matching events of
    a user within any `timeframe` window that ends in the epoch."""
    out: dict[tuple[str, str, int], float] = {}
    for rule in rules:
        times = defaultdict(list)
        for ev in events:
            if ev.cat in rule.categories:
                times[ev.user].append(ev.ts)
        for u, ts in times.items():
            ts.sort()
            for i, t in enumerate(ts):
                k = (u, rule.attack_class, int(t // epoch_len) + 1)
                out[k] = max(out.get(k, 0), i - bisect_left(ts, t - rule.timeframe) + 1)
    return out


def calibrate_rules(dev: SynthConfig, timeframe: float, target_fpr: float) -> list[FreqRule]:
    """B1-tuned: long timeframe, frequency = smallest value meeting the target FPR on dev."""
    events, _ = generate(benign(dev))
    allowed = math.floor(target_fpr * dev.n_users * dev.epochs)
    out = []
    for r in WAZUH_DEFAULT:
        f = 2
        while len(rule_alerts(events, [replace(r, frequency=f, timeframe=timeframe)], dev.epoch_len)) > allowed:
            f += 1
        out.append(replace(r, frequency=f, timeframe=timeframe))
    return out


# ============================================================================ output
def write_csv(name: str, rows: list[dict]) -> Path:
    RESULTS.mkdir(parents=True, exist_ok=True)
    path = RESULTS / name
    keys = list(dict.fromkeys(k for r in rows for k in r))
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, keys)
        w.writeheader()
        w.writerows(rows)
    return path


def write_json(name: str, obj) -> Path:
    RESULTS.mkdir(parents=True, exist_ok=True)
    path = RESULTS / name
    path.write_text(json.dumps(obj, indent=2, default=lambda o: asdict(o) if hasattr(o, "__dataclass_fields__") else str(o)))
    return path


def mean_sd(xs: list[float]) -> str:
    xs = [x for x in xs if x is not None and not (isinstance(x, float) and math.isnan(x))]
    if not xs:
        return "n/a"
    return f"{statistics.mean(xs):.3f} ± {statistics.stdev(xs):.3f}" if len(xs) > 1 else f"{xs[0]:.3f}"
