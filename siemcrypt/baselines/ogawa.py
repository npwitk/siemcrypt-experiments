"""B6: privacy-aware traffic log anonymization (Ogawa, Shimada, Hasegawa, Yamaguchi,
IEEE COMPSAC 2025), reproduced on Kyoto 2016.

Reimplemented from Sections III-IV:
  features  the 20 session features of Section II-C (IDS/malware/Ashula columns, start time and
            session ID excluded); ports -> well-known (< 1024) or not; IPs -> number of sessions
            in the last 500 with the same subnet identifier; service, flag, protocol one-hot
            (Section IV-A)
  anonymize service -> {smtp, http, ssh, dns, other}; destination and source bytes -> decade
            bins; duration -> decade bins (Section III-D); "-1 anonymization" replaces the same
            four features by -1 (Table III baseline)
  classify  LightGBM; 5,000 benign + 5,000 malicious training sessions and a disjoint
            balanced test set of the same size, per year (Section IV-A)
  privacy   k-anonymity of the classifier's feature vectors: share of sessions with k = 1
            and with k >= 5 (Section IV-C); uniqueness as an extra feature (Table IV)

Ambiguities resolved here: the duration bins are read as {0, (0, 0.01], (0.01, 0.1], (0.1, 1],
(1, 10], (10, 100], > 100} (the paper's "0.1 < s <= 0.1" is a typo) and the byte bins' last
rank as > 1 KB (the paper writes "> 10 KB", leaving (1 KB, 10 KB] unassigned).
Data: the raw Kyoto 2016 archive of 2015 (takakura.com, via the Internet Archive), one day per
month; fetched by tools/kyoto_fetch.py.
"""

from __future__ import annotations

import numpy as np

# Kyoto 2006+/2016 column order (24 fields)
COLS = ["duration", "service", "src_bytes", "dst_bytes", "count", "same_srv_rate", "serror_rate",
        "srv_serror_rate", "dst_host_count", "dst_host_srv_count", "dst_host_same_src_port_rate",
        "dst_host_serror_rate", "dst_host_srv_serror_rate", "flag", "ids_detection", "malware_detection",
        "ashula_detection", "label", "src_ip", "src_port", "dst_ip", "dst_port", "start_time", "protocol"]
NUMERIC = ["count", "same_srv_rate", "serror_rate", "srv_serror_rate", "dst_host_count", "dst_host_srv_count",
           "dst_host_same_src_port_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate"]
SENSITIVE = ["duration", "src_bytes", "dst_bytes", "service"]
DUR_EDGES = [0.0, 0.01, 0.1, 1.0, 10.0, 100.0]
BYTE_EDGES = [0.0, 10.0, 100.0, 1000.0]
SRC_EDGES = [1.0, 10.0, 100.0, 1000.0]
KEEP_SERVICES = ["smtp", "http", "ssh", "dns"]


def _bins(v: np.ndarray, edges: list[float], zero_rank: bool) -> np.ndarray:
    """One-hot decade ranks. zero_rank: a separate rank for v == 0 (duration, destination bytes)."""
    v = np.asarray(v, float)
    if zero_rank:
        idx = np.where(v <= 0, 0, 1 + np.searchsorted(edges[1:], v, side="left"))
        k = len(edges) + 1
    else:
        idx = np.searchsorted(edges, v, side="left")
        k = len(edges) + 1
    return np.eye(k)[np.clip(idx, 0, k - 1)]


def _subnet(ip: str) -> str:
    ip = str(ip)
    return ip.rsplit(":", 1)[0] if ":" in ip else ip.rsplit(".", 1)[0]


def _recent_same(keys: list[str], window: int = 500) -> np.ndarray:
    from collections import Counter, deque

    win, cnt, out = deque(), Counter(), np.zeros(len(keys))
    for i, k in enumerate(keys):
        out[i] = cnt[k]
        win.append(k)
        cnt[k] += 1
        if len(win) > window:
            cnt[win.popleft()] -= 1
    return out


def features(df, mode: str = "original", services: list[str] | None = None, flags: list[str] | None = None):
    """Classifier matrix for mode in {"original", "proposed", "minus1"}; df in time order."""
    cols, parts = [], []
    services = services or sorted(df["service"].astype(str).value_counts().index[:18]) + ["__other__"]
    flags = flags or sorted(df["flag"].astype(str).unique())

    def add(name, block):
        block = np.asarray(block, float)
        if block.ndim == 1:
            block = block[:, None]
        parts.append(block)
        cols.extend(f"{name}_{i}" for i in range(block.shape[1]))

    svc = df["service"].astype(str).to_numpy()
    if mode == "proposed":
        add("duration", _bins(df["duration"], DUR_EDGES, True))
        add("src_bytes", _bins(df["src_bytes"], SRC_EDGES, False))
        add("dst_bytes", _bins(df["dst_bytes"], BYTE_EDGES, True))
        lab = np.array([s if s in KEEP_SERVICES else "other" for s in svc])
        add("service", np.stack([lab == s for s in KEEP_SERVICES + ["other"]], 1))
    elif mode == "minus1":
        for f in ("duration", "src_bytes", "dst_bytes", "service"):
            add(f, -np.ones(len(df)))
    else:
        add("duration", df["duration"])
        add("src_bytes", df["src_bytes"])
        add("dst_bytes", df["dst_bytes"])
        lab = np.array([s if s in services else "__other__" for s in svc])
        add("service", np.stack([lab == s for s in services], 1))
    for c in NUMERIC:
        add(c, df[c])
    add("src_port", df["src_port"].astype(float) < 1024)
    add("dst_port", df["dst_port"].astype(float) < 1024)
    add("src_ip", _recent_same([_subnet(x) for x in df["src_ip"]]))
    add("dst_ip", _recent_same([_subnet(x) for x in df["dst_ip"]]))
    fl = df["flag"].astype(str).to_numpy()
    add("flag", np.stack([fl == f for f in flags], 1))
    pr = df["protocol"].astype(str).str.lower().to_numpy()
    add("protocol", np.stack([pr == p for p in ("tcp", "udp", "icmp")], 1))
    return np.hstack(parts), cols, services, flags


def k_anonymity(X: np.ndarray) -> np.ndarray:
    """k of every row = number of identical feature vectors in X."""
    _, inv, counts = np.unique(np.round(X, 9), axis=0, return_inverse=True, return_counts=True)
    return counts[inv.ravel()]


def lightgbm_eval(Xtr, ytr, Xte, yte, seed: int = 0) -> dict:
    import lightgbm as lgb

    clf = lgb.LGBMClassifier(random_state=seed, verbose=-1)
    clf.fit(Xtr, ytr)
    p = clf.predict(Xte)
    tp, tn = int(((p == 1) & (yte == 1)).sum()), int(((p == 0) & (yte == 0)).sum())
    fp, fn = int(((p == 1) & (yte == 0)).sum()), int(((p == 0) & (yte == 1)).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    return dict(acc=(tp + tn) / len(yte), prec=prec, rec=rec, f1=2 * prec * rec / (prec + rec) if prec + rec else 0.0)
