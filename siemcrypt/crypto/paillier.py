"""Paillier encryption [ref45] with offline randomizer precomputation (Phase 1).

Enc(m) = (1 + m N) * r^N mod N^2. The factor r^N mod N^2 does not depend on m, so a
pool of randomizers is precomputed offline; online encryption is then one modular
multiplication plus the cheap (1 + mN) term.

Homomorphic operations (Phase 3, eq:he-aggregation, eq:weighted-aggregation):
  add(c1, c2)  = c1 * c2 mod N^2      -> Enc(m1 + m2)
  smul(c, k)   = c^k mod N^2          -> Enc(k * m)
Decryption uses the CRT.
"""

from __future__ import annotations

import secrets
from collections import deque
from dataclasses import dataclass

import gmpy2
from gmpy2 import mpz


def _random_prime(bits: int) -> mpz:
    while True:
        cand = mpz(secrets.randbits(bits)) | (mpz(1) << (bits - 1)) | 1
        p = gmpy2.next_prime(cand)
        if p.bit_length() == bits:
            return p


@dataclass(frozen=True)
class PublicKey:
    n: mpz
    n2: mpz

    @property
    def bits(self) -> int:
        return int(self.n.bit_length())

    def ciphertext_bytes(self) -> int:
        return (int(self.n2.bit_length()) + 7) // 8


@dataclass(frozen=True)
class SecretKey:
    p: mpz
    q: mpz
    p2: mpz
    q2: mpz
    hp: mpz
    hq: mpz
    q_inv_p: mpz


def keygen(bits: int = 2048) -> tuple[PublicKey, SecretKey]:
    """(pk_H, sk_H) <- HE.KeyGen(1^lambda_sec), eq:he-keygen."""
    half = bits // 2
    while True:
        p, q = _random_prime(half), _random_prime(half)
        if p != q and gmpy2.gcd(p * q, (p - 1) * (q - 1)) == 1:
            break
    n = p * q
    p2, q2 = p * p, q * q
    g = n + 1
    # h_p = L_p(g^(p-1) mod p^2)^(-1) mod p, likewise for q.
    hp = gmpy2.invert((gmpy2.powmod(g, p - 1, p2) - 1) // p, p)
    hq = gmpy2.invert((gmpy2.powmod(g, q - 1, q2) - 1) // q, q)
    return PublicKey(n, n * n), SecretKey(p, q, p2, q2, hp, hq, gmpy2.invert(q, p))


class Paillier:
    """Encryptor with an optional pool of precomputed randomizers r^N mod N^2."""

    def __init__(self, pk: PublicKey):
        self.pk = pk
        self._pool: deque[mpz] = deque()
        self.online_randomizers = 0  # randomizers that had to be computed online
        self._executor = None

    # --- randomizers -------------------------------------------------------
    def _randomizer(self) -> mpz:
        n = self.pk.n
        while True:
            r = mpz(secrets.randbelow(int(n - 1))) + 1
            if gmpy2.gcd(r, n) == 1:
                return gmpy2.powmod(r, n, self.pk.n2)

    def precompute(self, count: int, workers: int = 1) -> None:
        """Offline phase: fill the randomizer pool, optionally on several cores."""
        if count <= 0:
            return
        if workers <= 1 or count < 4 * workers:
            for _ in range(count):
                self._pool.append(self._randomizer())
            return
        if self._executor is None or self._executor._max_workers != workers:
            from concurrent.futures import ProcessPoolExecutor

            self.close()
            self._executor = ProcessPoolExecutor(max_workers=workers)
        chunks = [count // workers + (1 if i < count % workers else 0) for i in range(workers)]
        for batch in self._executor.map(_randomizer_batch, [int(self.pk.n)] * workers, chunks):
            self._pool.extend(mpz(x) for x in batch)

    def close(self) -> None:
        """Shut down the precomputation workers, if any."""
        if self._executor is not None:
            self._executor.shutdown()
            self._executor = None

    def pool_size(self) -> int:
        return len(self._pool)

    # --- operations --------------------------------------------------------
    def encrypt(self, m: int) -> mpz:
        if self._pool:
            rn = self._pool.popleft()
        else:
            self.online_randomizers += 1
            rn = self._randomizer()
        n, n2 = self.pk.n, self.pk.n2
        return (1 + (mpz(m) % n) * n) * rn % n2

    def add(self, c1: mpz, c2: mpz) -> mpz:
        return c1 * c2 % self.pk.n2

    def smul(self, c: mpz, k: int) -> mpz:
        return gmpy2.powmod(c, mpz(k) % self.pk.n, self.pk.n2)

    def sum(self, cts) -> mpz:
        acc = mpz(1)  # Enc(0) with randomizer 1; fine as an additive identity
        n2 = self.pk.n2
        for c in cts:
            acc = acc * c % n2
        return acc


def _randomizer_batch(n: int, count: int) -> list[int]:
    """Worker for parallel precomputation: `count` values r^N mod N^2."""
    n_m, n2 = mpz(n), mpz(n) * mpz(n)
    out = []
    while len(out) < count:
        r = mpz(secrets.randbelow(n - 1)) + 1
        if gmpy2.gcd(r, n_m) == 1:
            out.append(int(gmpy2.powmod(r, n_m, n2)))
    return out


def decrypt(sk: SecretKey, pk: PublicKey, c: mpz) -> int:
    """HE.Dec_{sk_H}(c) via the CRT; returns a value in [0, N)."""
    mp = (gmpy2.powmod(c, sk.p - 1, sk.p2) - 1) // sk.p * sk.hp % sk.p
    mq = (gmpy2.powmod(c, sk.q - 1, sk.q2) - 1) // sk.q * sk.hq % sk.q
    m = mq + ((mp - mq) * sk.q_inv_p % sk.p) * sk.q
    return int(m % pk.n)
