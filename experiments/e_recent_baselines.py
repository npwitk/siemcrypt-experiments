"""2024-2026 journal baselines B10-B13 (siemcrypt/baselines/recent.py) against SIEMCrypt.

Measures the unit costs every model needs on this machine (gmpy2 Paillier, the code SIEMCrypt
uses; RSA with gmpy2 CRT; AES-256-GCM from `cryptography`), then prices
  Part A  protection cost per event at 2048-bit keys, offline work included (Exp 2):
          S (HE encryptions per event from tab:e3-volume), B10 Zhang, B11 Naresh (F = 77 and 3),
          B12 Ji (ref7, policy P3); the measured EVSEB, MK-Tree and PriSIEM rows stay as they are
  Part B  verification of k records out of n (Exp 6): B10 Zhang and B13 Wu next to the measured
          S / EVSEB / MK-Tree / Zhang-2023 rows of baselines_verify.csv

Usage:  python experiments/e_recent_baselines.py [--iters 200]
Writes results/recent_units.csv, recent_baselines.csv and recent_baselines.md.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import os
import platform
import secrets
import statistics
import sys
import time
from pathlib import Path

import gmpy2
from gmpy2 import mpz

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import RESULTS, write_csv  # noqa: E402

from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402

from siemcrypt.baselines import recent  # noqa: E402
from siemcrypt.crypto import paillier  # noqa: E402

GRID = [(1_000, 10), (1_000, 1_000), (10_000, 10), (10_000, 1_000), (100_000, 10), (100_000, 1_000)]
HE_PER_EVENT = {"S-NoPad": 3.00, "S, k=3": 4.02, "S, k=5": 5.10}  # tab:e3-volume (synthetic)


def bench(fn, iters: int) -> float:
    ts = []
    for _ in range(iters):
        t0 = time.perf_counter()
        fn()
        ts.append(time.perf_counter() - t0)
    return statistics.median(ts) * 1e6


def rsa_keygen(bits: int = 2048):
    e = mpz(65537)
    while True:
        p, q = paillier._random_prime(bits // 2), paillier._random_prime(bits // 2)
        phi = (p - 1) * (q - 1)
        if p != q and gmpy2.gcd(e, phi) == 1:
            d = gmpy2.invert(e, phi)
            return dict(n=p * q, e=e, p=p, q=q, dp=d % (p - 1), dq=d % (q - 1), qinv=gmpy2.invert(q, p))


def rsa_priv(k, m):  # CRT private exponentiation (sign / blind-sign / decrypt)
    mp, mq = gmpy2.powmod(m, k["dp"], k["p"]), gmpy2.powmod(m, k["dq"], k["q"])
    return mq + (mp - mq) * k["qinv"] % k["p"] * k["q"]


def units(iters: int) -> dict[str, float]:
    u = {}
    pk2, sk2 = paillier.keygen(2048)
    P2 = paillier.Paillier(pk2)
    c2 = P2.encrypt(12345)
    u["paillier2048_enc"] = bench(lambda: P2.encrypt(12345), iters)  # no precomputed r^N
    u["paillier2048_dec"] = bench(lambda: paillier.decrypt(sk2, pk2, c2), iters)
    pk1, sk1 = paillier.keygen(1024)
    c1 = paillier.Paillier(pk1).encrypt(12345)
    u["paillier1024_dec"] = bench(lambda: paillier.decrypt(sk1, pk1, c1), iters)
    k = rsa_keygen(2048)
    m = mpz(secrets.randbits(2000))
    s = rsa_priv(k, m)
    u["rsa_priv"] = bench(lambda: rsa_priv(k, m), iters)
    u["rsa_pub"] = bench(lambda: gmpy2.powmod(s, k["e"], k["n"]), iters * 5)
    key = AESGCM(os.urandom(32))
    field = os.urandom(24)

    def enc_field():  # B12: fresh 96-bit nonce, AES-256-GCM, base64url token
        n = os.urandom(12)
        base64.urlsafe_b64encode(n + key.encrypt(n, field, None))

    u["aes_field"] = bench(enc_field, iters * 20)
    payload = os.urandom(512)
    u["aes_payload"] = bench(lambda: key.encrypt(os.urandom(12), payload, None), iters * 20)
    blob = os.urandom(64)
    u["hash"] = bench(lambda: hashlib.sha256(blob).digest(), iters * 50)
    kk = os.urandom(32)
    u["prf"] = bench(lambda: hmac.new(kk, hashlib.sha256(blob).digest(), "sha256").digest(), iters * 50)
    return u


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--iters", type=int, default=200)
    a = ap.parse_args()
    t0 = time.time()
    u = units(a.iters)
    env = f"{platform.platform()} / {platform.processor() or platform.machine()} / Python {platform.python_version()}"
    write_csv("recent_units.csv", [dict(symbol=k, median_us=v) for k, v in u.items()] + [dict(symbol="env", median_us=env)])

    rows = []
    for name, he in HE_PER_EVENT.items():
        rows.append(dict(part="A", system=name, us_per_event=recent.siemcrypt_event_us(u, he), bytes_per_event=None,
                         analytics="yes (Paillier, exact)", note=f"{he} HE enc / real event"))
    rows += [
        dict(part="A", system="B10 Zhang 2025", us_per_event=recent.zhang_event_us(u),
             bytes_per_event=recent.zhang_event_bytes(), analytics="no", note="Paillier CID + RSA blind sig + RSA sig"),
        dict(part="A", system="B11 Naresh 2025, F=77", us_per_event=recent.naresh_event_us(u, 77),
             bytes_per_event=recent.naresh_event_bytes(77), analytics="no (model on ciphertext values)",
             note="one Paillier ciphertext per flow feature"),
        dict(part="A", system="B11 Naresh 2025, F=3", us_per_event=recent.naresh_event_us(u, 3),
             bytes_per_event=recent.naresh_event_bytes(3), analytics="no (model on ciphertext values)",
             note="favourable case: our 3 features"),
        dict(part="A", system="B12 Ji 2026 (ref7), P3", us_per_event=recent.ji_event_us(u, 5),
             bytes_per_event=recent.JI_EVENT_BYTES_P3, analytics="no", note="5 AES-GCM fields"),
    ]
    for n, k in GRID:
        rows.append(dict(part="B", system="B10 Zhang 2025", n=n, k=k, verify_ms=recent.zhang_verify_ms(k, u)))
        rows.append(dict(part="B", system="B13 Wu 2025 (lower bound)", n=n, k=k, verify_ms=recent.wu_verify_ms(k, u)))
    write_csv("recent_baselines.csv", rows)

    md = ["# 2024-2026 journal baselines (B10-B13) against SIEMCrypt", "", f"Machine: {env}. Unit costs (median µs):", "",
          "| Unit | µs |", "|---|---|"] + [f"| {k} | {v:,.3f} |" for k, v in u.items()]
    md += ["", "## A. Protection cost per event (2048-bit keys, offline work included, one core)", "",
           "| System | µs / event | bytes / event | encrypted analytics | note |", "|---|---|---|---|---|"]
    for r in rows:
        if r["part"] == "A":
            b = "-" if r["bytes_per_event"] is None else f"{r['bytes_per_event']:,}"
            md.append(f"| {r['system']} | {r['us_per_event']:,.1f} | {b} | {r['analytics']} | {r['note']} |")
    md += ["", "## B. Verifying k records out of n (ms)", "", "| n | k | B10 Zhang 2025 | B13 Wu 2025 (lower bound) |",
           "|---|---|---|---|"]
    for n, k in GRID:
        z = next(r for r in rows if r["part"] == "B" and r["n"] == n and r["k"] == k and r["system"].startswith("B10"))
        w = next(r for r in rows if r["part"] == "B" and r["n"] == n and r["k"] == k and r["system"].startswith("B13"))
        md.append(f"| {n:,} | {k:,} | {z['verify_ms']:,.1f} | {w['verify_ms']:,.1f} |")
    md += ["", "B13 counts only the user's 2(2L+2) Paillier-1024 decryptions with L = k and one keyword; root finding, "
           "server search and the trapdoor are excluded, so it is a lower bound. Neither B10 nor B13 depends on n.",
           f"\nTotal time {time.time() - t0:.0f}s"]
    (RESULTS / "recent_baselines.md").write_text("\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    main()
