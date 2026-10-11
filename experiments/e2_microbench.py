"""E2 microbenchmarks: measured unit costs for the Section IV cost table.

Usage:  python experiments/e2_microbench.py [--bits 2048] [--quick]
Writes results/e2_microbench.csv and prints a Markdown table.
All numbers in the paper must come from one machine (the evaluation VM).
"""

from __future__ import annotations

import argparse
import csv
import os
import platform
import random
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from siemcrypt.crypto import mmr, paillier  # noqa: E402
from siemcrypt.crypto.cms import CountMin  # noqa: E402
from siemcrypt.crypto.encoding import encode  # noqa: E402
from siemcrypt.crypto.primitives import (  # noqa: E402
    H,
    Signer,
    aead_decrypt,
    aead_encrypt,
    kdf,
    prf_token,
    verify,
)


def bench(fn, iters: int, setup=None) -> float:
    """Median time per call in microseconds."""
    samples = []
    for _ in range(iters):
        arg = setup() if setup else None
        t0 = time.perf_counter_ns()
        fn(arg) if setup else fn()
        samples.append(time.perf_counter_ns() - t0)
    return statistics.median(samples) / 1000.0


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bits", type=int, default=2048, help="Paillier modulus size")
    ap.add_argument("--quick", action="store_true", help="fewer iterations")
    ap.add_argument("--out", default="results/e2_microbench.csv")
    args = ap.parse_args()
    k = 0.1 if args.quick else 1.0
    it = lambda n: max(5, int(n * k))  # noqa: E731

    rows: list[tuple[str, str, float, str]] = []

    def add(symbol: str, desc: str, us: float, note: str = "") -> None:
        rows.append((symbol, desc, us, note))
        print(f"  {symbol:<22} {us:12.2f} us  {desc}", flush=True)

    print(f"SIEMCrypt microbenchmarks (Paillier {args.bits}-bit)")
    msk = os.urandom(32)
    key_p, key_u = kdf(msk, "P", 1), kdf(msk, "U", 1)
    payload, ad = os.urandom(512), encode(1, 3, "meta")
    blob64 = os.urandom(64)

    add("T_H", "SHA-256, 64-byte input", bench(lambda: H(blob64), it(20000)))
    add("T_PRF", "token F_K(H(v)) = HMAC-SHA256(SHA-256(v))", bench(lambda: prf_token(key_u, "alice@corp"), it(20000)))
    add("T_KDF", "HKDF-SHA256 epoch key", bench(lambda: kdf(msk, "R", 5), it(5000)))
    iv, ct = aead_encrypt(key_p, payload, ad)
    add("T_AES (enc)", "AES-256-GCM, 512-byte payload", bench(lambda: aead_encrypt(key_p, payload, ad), it(20000)))
    add("T_AES (dec)", "AES-256-GCM, 512-byte payload", bench(lambda: aead_decrypt(key_p, iv, ct, ad), it(20000)))

    t0 = time.perf_counter()
    pk, sk = paillier.keygen(args.bits)
    add("KeyGen", f"Paillier {args.bits}-bit (one-time)", (time.perf_counter() - t0) * 1e6)
    P = paillier.Paillier(pk)
    add("T_rand (offline)", "precompute r^N mod N^2", bench(lambda: P.precompute(1), it(200)))
    P._pool.clear()
    add("T_Enc (online)", "Paillier encryption without precomputation", bench(lambda: P.encrypt(12345), it(200)))
    n_pre = it(2000)
    P.precompute(n_pre)
    add("T_Enc", "Paillier encryption with precomputed r^N", bench(lambda: P.encrypt(12345), n_pre - 1))
    P.precompute(4)
    c1, c2 = P.encrypt(1000), P.encrypt(2000)
    add("T_Add", "homomorphic addition (mod N^2 multiplication)", bench(lambda: P.add(c1, c2), it(20000)))
    add("T_SMul", "plaintext-ciphertext multiplication, 16-bit weight", bench(lambda: P.smul(c1, 40503), it(2000)))
    add("T_Dec", "Paillier CRT decryption", bench(lambda: paillier.decrypt(sk, pk, c1), it(500)))

    s = Signer()
    msg = os.urandom(96)
    sig = s.sign(msg)
    add("T_Sig", "Ed25519 sign (checkpoint)", bench(lambda: s.sign(msg), it(5000)))
    add("T_Ver", "Ed25519 verify (checkpoint)", bench(lambda: verify(s.pk, msg, sig), it(5000)))

    # MMR: amortized append and multiproof verification
    n = 1 << 16
    t = mmr.MMR()
    leaves = [mmr.leaf_hash(encode(i, os.urandom(32), os.urandom(32))) for i in range(n)]
    t0 = time.perf_counter_ns()
    for lh in leaves:
        t.append_leaf_hash(lh)
    add("MMR append", f"amortized per leaf (n={n}), excl. leaf hash", (time.perf_counter_ns() - t0) / n / 1000.0)
    root = t.root()
    rng = random.Random(0)
    for kk in (1, 16, 256):
        idx = rng.sample(range(n), kk)
        proof = t.multiprove(idx)
        sub = {i: leaves[i] for i in idx}
        us = bench(lambda: mmr.multiverify(sub, proof, root, n), it(200))
        add(f"MultiVerify k={kk}", f"n={n}; proof={mmr.proof_size(proof)} hashes "
            f"(vs {kk * (n.bit_length() - 1)} for separate paths)", us)

    cms = CountMin.for_error(0.001, 0.01)
    add("CMS update", f"Count-Min update, {cms.d}x{cms.w}", bench(lambda: cms.update(b"user42"), it(20000)))

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["symbol", "description", "median_us", "note"])
        w.writerows(rows)
        w.writerow([])
        w.writerow(["env", platform.platform(), platform.processor() or platform.machine(), sys.version.split()[0]])
        w.writerow(["paillier_bits", args.bits, "ciphertext_bytes", pk.ciphertext_bytes()])

    print(f"\nCiphertext size: {pk.ciphertext_bytes()} bytes per Paillier ciphertext")
    print(f"Environment: {platform.platform()} | Python {sys.version.split()[0]}")
    print(f"Wrote {out}\n")
    print("| Symbol | Operation | Median (µs) |\n|---|---|---|")
    for sym, desc, us, _ in rows:
        print(f"| `{sym}` | {desc} | {us:,.2f} |")


if __name__ == "__main__":
    main()
