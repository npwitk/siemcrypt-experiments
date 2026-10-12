"""B4: privacy-preserving network anomaly detection on homomorphically encrypted data
(Wingarz, See, Gondesen, Fischer, IEEE CNS 2024).

Reimplemented from Sections III-IV:
  data   CSE-CIC-IDS2018, 80 CICFlowMeter features; rows with NaN/inf removed; constant
         features removed; one feature of every pair with correlation 1 removed (64 features),
         then of every pair above 0.99 (50 features); min-max normalization; 80/10/10 split;
         binary label benign / attack (Section IV-B)
  model  Baseline50 = lin(50, 9) -> x^2 -> lin(9, 4) -> x^2 -> lin(4, 2); the class is the larger
         output (Table II); cross-entropy weighted 1:15 toward attacks, Adagrad, up to 150
         epochs, learning rate halved after 10 epochs without improvement and training stopped
         after the fourth halving (Section III-A.3)
  CKKS   N = 16384, q = [60, 40, 40, 40, 40, 40, 60] bits, scale 2^40, depth 5 (Table V);
         a batch of N/2 = 8192 input vectors is packed feature by feature, so feature i of the
         whole batch is one ciphertext; the server evaluates the network slot-wise and returns
         two encrypted output vectors (Section III-B.2, "CKKS50")

The paper uses SEAL-Python 4.0; this uses TenSEAL 0.3, also built on Microsoft SEAL.
Modelling choices (not fixed by the paper): mini-batch size 4096, initial learning rate 0.01
(Adagrad's default), and correlations computed on a random sample of 10^6 rows.
"""

from __future__ import annotations

import time
from pathlib import Path

import numpy as np

LABEL, TS = "Label", "Timestamp"
EXTRA = ["Flow ID", "Src IP", "Src Port", "Dst IP"]  # present only in the 20-02-2018 file
BATCH = 8192


def load(paths: list[Path], max_rows: int | None = None, seed: int = 0):
    """Section IV-B preprocessing. Returns (X float32, y int8, feature names)."""
    import pandas as pd

    frames = []
    for p in paths:
        df = pd.read_csv(p, low_memory=False)
        df = df[df[LABEL] != LABEL]                       # repeated header lines inside some files
        df = df.drop(columns=[c for c in EXTRA + [TS] if c in df.columns])
        frames.append(df)
    df = pd.concat(frames, ignore_index=True)
    if max_rows and len(df) > max_rows:
        df = df.sample(max_rows, random_state=seed)
    y = (df.pop(LABEL).astype(str) != "Benign").to_numpy(np.int8)
    X = df.apply(pd.to_numeric, errors="coerce").to_numpy(np.float64)
    ok = np.isfinite(X).all(axis=1)
    X, y = X[ok], y[ok]
    names = list(df.columns)
    keep = X.std(axis=0) > 0                              # constant features
    X, names = X[:, keep], [n for n, k in zip(names, keep) if k]
    return X.astype(np.float32), y, names, float(1 - ok.mean())


def drop_correlated(X: np.ndarray, names: list[str], thr: float, sample: int = 1_000_000, seed: int = 0):
    """Remove one feature of every pair whose |correlation| >= thr (later index removed)."""
    rng = np.random.default_rng(seed)
    S = X[rng.choice(len(X), min(sample, len(X)), replace=False)].astype(np.float64)
    C = np.abs(np.corrcoef(S, rowvar=False))
    drop = set()
    for i in range(C.shape[0]):
        if i in drop:
            continue
        for j in range(i + 1, C.shape[0]):
            if j not in drop and C[i, j] >= thr - 1e-12:
                drop.add(j)
    keep = [i for i in range(X.shape[1]) if i not in drop]
    return X[:, keep], [names[i] for i in keep]


def minmax(X_train: np.ndarray, *others: np.ndarray):
    lo, hi = X_train.min(axis=0), X_train.max(axis=0)
    span = np.where(hi > lo, hi - lo, 1.0)
    return [(A - lo) / span for A in (X_train, *others)]


def train(Xtr, ytr, Xva, yva, epochs: int = 150, batch: int = 4096, lr: float = 0.01, seed: int = 0, log=print):
    import torch
    from torch import nn

    torch.manual_seed(seed)

    class Sq(nn.Module):
        def forward(self, x):
            return x * x

    d = Xtr.shape[1]
    model = nn.Sequential(nn.Linear(d, 9), Sq(), nn.Linear(9, 4), Sq(), nn.Linear(4, 2))
    loss_fn = nn.CrossEntropyLoss(weight=torch.tensor([1.0, 15.0]))
    opt = torch.optim.Adagrad(model.parameters(), lr=lr)
    sched = torch.optim.lr_scheduler.ReduceLROnPlateau(opt, mode="max", factor=0.5, patience=10)
    Xt, yt = torch.from_numpy(Xtr), torch.from_numpy(ytr.astype(np.int64))
    Xv, yv = torch.from_numpy(Xva), torch.from_numpy(yva.astype(np.int64))
    best, best_state, halvings, last_lr = -1.0, None, 0, lr
    for ep in range(epochs):
        model.train()
        perm = torch.randperm(len(Xt))
        for k in range(0, len(Xt), batch):
            idx = perm[k:k + batch]
            opt.zero_grad()
            loss_fn(model(Xt[idx]), yt[idx]).backward()
            opt.step()
        model.eval()
        with torch.no_grad():
            acc = (model(Xv).argmax(1) == yv).float().mean().item()
        if acc > best:
            best, best_state = acc, {k: v.clone() for k, v in model.state_dict().items()}
        sched.step(acc)
        cur = opt.param_groups[0]["lr"]
        if cur < last_lr:
            halvings, last_lr = halvings + 1, cur
            if halvings >= 4:
                log(f"  stop after the 4th learning-rate halving (epoch {ep + 1})")
                break
        if ep % 10 == 0:
            log(f"  epoch {ep + 1}: validation accuracy {acc:.4f}")
    model.load_state_dict(best_state)
    return [(m.weight.detach().numpy().astype(np.float64), m.bias.detach().numpy().astype(np.float64))
            for m in model if isinstance(m, torch.nn.Linear)]


def plain_predict(layers, X: np.ndarray) -> np.ndarray:
    h = X.astype(np.float64)
    for k, (W, b) in enumerate(layers):
        h = h @ W.T + b
        if k < len(layers) - 1:
            h = h * h
    return h.argmax(1)


def ckks_context():
    import tenseal as ts

    ctx = ts.context(ts.SCHEME_TYPE.CKKS, poly_modulus_degree=16384,
                     coeff_mod_bit_sizes=[60, 40, 40, 40, 40, 40, 60])     # Table V, "Float"
    ctx.global_scale = 2 ** 40
    return ctx


def ckks_infer(ctx, layers, Xb: np.ndarray) -> tuple[np.ndarray, dict]:
    """Encrypt a batch (<= 8192 vectors) feature-wise, evaluate the network on ciphertexts,
    decrypt the two outputs. Returns predictions and timings / sizes."""
    import tenseal as ts

    t0 = time.perf_counter()
    cts = [ts.ckks_vector(ctx, Xb[:, i].tolist()) for i in range(Xb.shape[1])]   # client
    t_enc = time.perf_counter() - t0
    size = sum(len(c.serialize()) for c in cts)
    t1 = time.perf_counter()
    h = cts
    for k, (W, b) in enumerate(layers):                                          # server
        nxt = []
        for r in range(W.shape[0]):
            acc = h[0] * float(W[r, 0])
            for i in range(1, len(h)):
                acc += h[i] * float(W[r, i])
            acc += float(b[r])
            if k < len(layers) - 1:
                acc = acc * acc                                                  # square activation
            nxt.append(acc)
        h = nxt
    t_eval = time.perf_counter() - t1
    t2 = time.perf_counter()
    out = np.stack([np.array(c.decrypt()[:len(Xb)]) for c in h], axis=1)         # client
    t_dec = time.perf_counter() - t2
    return out.argmax(1), dict(enc_s=t_enc, eval_s=t_eval, dec_s=t_dec, batch_bytes=size, vectors=len(Xb))


def metrics(y: np.ndarray, p: np.ndarray) -> dict:
    tp = int(((p == 1) & (y == 1)).sum())
    tn = int(((p == 0) & (y == 0)).sum())
    fp = int(((p == 1) & (y == 0)).sum())
    fn = int(((p == 0) & (y == 1)).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    return dict(acc=(tp + tn) / len(y), prec=prec, rec=rec, f1=2 * prec * rec / (prec + rec) if prec + rec else 0.0,
                tp=tp, tn=tn, fp=fp, fn=fn)
