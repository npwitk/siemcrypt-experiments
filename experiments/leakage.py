"""Leakage attacks of E3 on the Cloud SIEM's view (index entries, bucket labels, record
sizes, releases). Ground truth comes from the EE's token cache and decoy record set, which
the attacks never read; they are used only to score the attacks.

  frequency_attack     rank-matching frequency analysis against an auxiliary distribution
  decoy_distinguisher  classifier separating decoy from real records (AUC; 0.5 is ideal)
  linkage_attack       matching entity tokens across consecutive epochs
"""

from __future__ import annotations

from collections import Counter, defaultdict

import numpy as np

from siemcrypt.model import Event
from siemcrypt.system import SIEMCrypt

DIM_POS = {"U": 0, "R": 1, "C": 2, "S": 3}
ATTR = {"U": "user", "R": "res", "C": "cat", "S": "src"}


# ============================================================================ ground truth
def token_truth(s: SIEMCrypt) -> dict[tuple[int, str], dict[bytes, str]]:
    """(epoch, dim) -> token -> plaintext value, from the EE's cache (evaluation only)."""
    out = defaultdict(dict)
    for (e, dim, value), tok in s.ee._tok_cache.items():
        out[(e, dim)][tok] = value
    return out


def entries_by_epoch(s: SIEMCrypt) -> dict[int, list]:
    out = defaultdict(list)
    for rid, ent in s.cloud.entries.items():
        out[rid[0]].append((rid, ent))
    return out


# ============================================================================ (a) frequency
def aux_distribution(events: list[Event], dim: str) -> list[str]:
    """Values ranked by frequency in the adversary's auxiliary data."""
    return [v for v, _ in Counter(getattr(ev, ATTR[dim]) for ev in events).most_common()]


def frequency_attack(s: SIEMCrypt, aux_rank: list[str], dim: str, cumulative: bool = False) -> dict:
    """Map the i-th most frequent token to the i-th most frequent auxiliary value.

    cumulative=True accumulates counts over all epochs, which is possible only when tokens
    do not rotate (A4 / static tokens): equal tokens then denote the same value.
    Returns token recovery (fraction of real tokens) and volume recovery (fraction of real
    records whose token is mapped correctly), averaged over epochs.
    """
    truth = token_truth(s)
    by_ep = entries_by_epoch(s)
    pos = DIM_POS[dim]
    tok_rates, vol_rates = [], []
    acc = Counter()
    for e in sorted(by_ep):
        cnt = Counter(ent.tokens[pos] for _, ent in by_ep[e])
        if cumulative:
            acc.update(cnt)
            cnt = acc
        guess = {tok: aux_rank[i] if i < len(aux_rank) else None
                 for i, (tok, _) in enumerate(cnt.most_common())}
        real = truth[(e, dim)] if not cumulative else {t: v for (ep, d), m in truth.items() if d == dim for t, v in m.items()}
        real_cur = {t: real[t] for t in Counter(ent.tokens[pos] for _, ent in by_ep[e]) if t in real}
        if not real_cur:
            continue
        ok = [t for t, v in real_cur.items() if guess.get(t) == v]
        tok_rates.append(len(ok) / len(real_cur))
        n_real = sum(1 for rid, ent in by_ep[e] if rid not in s.ee.decoy_rids)
        n_ok = sum(1 for rid, ent in by_ep[e] if rid not in s.ee.decoy_rids and ent.tokens[pos] in set(ok))
        vol_rates.append(n_ok / max(n_real, 1))
    return dict(token_recovery=float(np.mean(tok_rates)), volume_recovery=float(np.mean(vol_rates)))


# ============================================================================ (b) decoys
def record_features(s: SIEMCrypt) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Per-record features computable by the cloud, labels (1 = decoy), and epochs."""
    by_ep = entries_by_epoch(s)
    X, y, ep = [], [], []
    for e, items in by_ep.items():
        u_ep = Counter(ent.tokens[0] for _, ent in items)
        r_ep = Counter(ent.tokens[1] for _, ent in items)
        u_b = Counter((ent.bucket, ent.tokens[0]) for _, ent in items)
        r_b = Counter((ent.bucket, ent.tokens[1]) for _, ent in items)
        cs_b = Counter((ent.bucket, ent.tokens[2], ent.tokens[3]) for _, ent in items)
        b_size = Counter(ent.bucket for _, ent in items)
        u_buckets = defaultdict(set)
        r_buckets = defaultdict(set)
        u_res = defaultdict(set)
        u_cats = defaultdict(set)
        for _, ent in items:
            u_buckets[ent.tokens[0]].add(ent.bucket)
            r_buckets[ent.tokens[1]].add(ent.bucket)
            u_res[ent.tokens[0]].add(ent.tokens[1])
            u_cats[ent.tokens[0]].add(ent.tokens[2])
        for rid, ent in items:
            tu, tr, tc, ts = ent.tokens
            rec = s.cloud.records[rid]
            X.append([u_ep[tu], r_ep[tr], u_b[(ent.bucket, tu)], r_b[(ent.bucket, tr)],
                      cs_b[(ent.bucket, tc, ts)], b_size[ent.bucket], len(u_buckets[tu]),
                      len(r_buckets[tr]), len(u_res[tu]), len(u_cats[tu]), len(rec.ct)])
            y.append(int(rid in s.ee.decoy_rids))
            ep.append(e)
    return np.array(X, float), np.array(y), np.array(ep)


def decoy_distinguisher(s: SIEMCrypt) -> dict:
    """Random forest trained on the first half of the epochs, tested on the second half."""
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import accuracy_score, roc_auc_score

    X, y, ep = record_features(s)
    if y.sum() == 0:
        return dict(auc=None, accuracy=None, decoy_share=0.0)
    cut = np.median(np.unique(ep))
    tr, te = ep <= cut, ep > cut
    clf = RandomForestClassifier(n_estimators=200, min_samples_leaf=5, random_state=0, n_jobs=1)
    clf.fit(X[tr], y[tr])
    p = clf.predict_proba(X[te])[:, 1]
    base = max(y[te].mean(), 1 - y[te].mean())
    return dict(auc=float(roc_auc_score(y[te], p)), accuracy=float(accuracy_score(y[te], p >= 0.5)),
                majority_baseline=float(base), decoy_share=float(y.mean()))


# ============================================================================ (c) linkage
def _link_small_dim(cnt_a: Counter, cnt_b: Counter) -> dict[bytes, bytes]:
    """Link category/source tokens of two epochs by volume rank (few, distinct values)."""
    ra = [t for t, _ in cnt_a.most_common()]
    rb = [t for t, _ in cnt_b.most_common()]
    return dict(zip(ra, rb))


def _profiles(items, cat_map, src_map, cats, srcs):
    prof = defaultdict(lambda: np.zeros(len(cats) + len(srcs) + 3))
    res, buckets = defaultdict(set), defaultdict(set)
    ci = {c: i for i, c in enumerate(cats)}
    si = {x: i for i, x in enumerate(srcs)}
    for _, ent in items:
        tu, tr, tc, ts = ent.tokens
        v = prof[tu]
        c = cat_map.get(tc, tc)
        x = src_map.get(ts, ts)
        if c in ci:
            v[ci[c]] += 1
        if x in si:
            v[len(cats) + si[x]] += 1
        v[-3] += 1
        res[tu].add(tr)
        buckets[tu].add(ent.bucket)
    for tu, v in prof.items():
        v[-2], v[-1] = len(res[tu]), len(buckets[tu])
    return prof


def linkage_attack(s: SIEMCrypt) -> dict:
    """For consecutive epochs e, e+1: link C and S tokens by volume, build per-entity
    profiles (category and source volumes, total, distinct resources, active buckets) and
    match entity tokens by minimum-cost assignment. Accuracy = fraction of real entities
    active in both epochs whose epoch-e token is matched to their epoch-(e+1) token."""
    from scipy.optimize import linear_sum_assignment

    truth = token_truth(s)
    by_ep = entries_by_epoch(s)
    eps = sorted(by_ep)
    accs = []
    for e1, e2 in zip(eps, eps[1:]):
        A, B = by_ep[e1], by_ep[e2]
        uA = {t: u for t, u in truth[(e1, "U")].items()}
        uB = {u: t for t, u in truth[(e2, "U")].items()}
        tokA = {ent.tokens[0] for _, ent in A}
        tokB = {ent.tokens[0] for _, ent in B}
        targets = {t: uB[u] for t, u in uA.items() if t in tokA and u in uB and uB[u] in tokB}
        if not targets:
            continue
        if tokA & tokB:  # tokens do not rotate: equal tokens link trivially
            accs.append(sum(1 for t, t2 in targets.items() if t == t2) / len(targets))
            continue
        cA, cB = Counter(ent.tokens[2] for _, ent in A), Counter(ent.tokens[2] for _, ent in B)
        sA, sB = Counter(ent.tokens[3] for _, ent in A), Counter(ent.tokens[3] for _, ent in B)
        cmap, smap = _link_small_dim(cA, cB), _link_small_dim(sA, sB)
        cats, srcs = list(cB), list(sB)
        pA = _profiles(A, cmap, smap, cats, srcs)
        pB = _profiles(B, {}, {}, cats, srcs)
        la, lb = list(pA), list(pB)
        MA = np.array([pA[t] for t in la])
        MB = np.array([pB[t] for t in lb])
        scale = np.maximum(np.vstack([MA, MB]).std(axis=0), 1e-9)
        cost = np.abs((MA[:, None, :] - MB[None, :, :]) / scale).sum(axis=2)
        ri, ci = linear_sum_assignment(cost)
        match = {la[i]: lb[j] for i, j in zip(ri, ci)}
        accs.append(sum(1 for t, t2 in targets.items() if match.get(t) == t2) / len(targets))
    return dict(linkage_accuracy=float(np.mean(accs)) if accs else None,
                chance=float(np.mean([1 / max(len({ent.tokens[0] for _, ent in by_ep[e]}), 1) for e in eps])))
