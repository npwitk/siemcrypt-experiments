"""B9: blockchain-based integrity auditing of Zhang, Qian, Cui, Zhong, Wang, He,
"Blockchain-Based Privacy-Preserving Deduplication and Integrity Auditing in Cloud Storage",
IEEE Trans. Computers 74(5), 2025.

Only the integrity-auditing part is reimplemented (Sections V-B, V-C.1 and V-D); the
deduplication, proof-of-ownership and IBBE key recovery serve shared file storage and have
no counterpart in a single-owner log stream. Each epoch of logs is one file F whose blocks
are the records, split into s sectors.

  setup    generators, chi in G1, H4: {0,1}* -> G1 (try-and-increment), audit key
           ak = {x, s_a}, pk = g^(H3(k_l) * s_a) (Section V-C.1)
  tags     tau_i = [H4(c_i || i) * chi^(sum_j c_ij)]^(H3(k_l)) (eq. 1)
  audit    the smart contract derives r3, r4 from the chain and challenges l2 blocks:
           a_i = pi1(i, r3), b_i = pi2(i, r4); the CSP answers p_j = sum x b_i c_(a_i, j),
           Psi = (prod tau_(a_i)^(b_i))^(s_a x), Gamma = (prod H4(c_(a_i) || a_i)^(b_i))^x (eq. 7);
           the contract checks e(Gamma * chi^theta, pk) = e(Psi, g) with theta = sum_j p_j (eq. 8)

The paper writes a symmetric pairing e: G1 x G1 -> G2 and implements it on BN254 with PBC;
on the asymmetric BN254 of py_ecc the tags live in G1 and pk in G2. py_ecc is pure Python,
so this module checks correctness and detection; timings come from the measured unit
costs of tools/pairing_bench (arkworks BN254) and the paper's cost formulas (Section VII-A).
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass

from py_ecc.optimized_bn128 import (
    G1, G2, FQ, add, b as CURVE_B, curve_order as R, field_modulus as P, multiply, pairing, Z1,
)

SECTOR = 128  # bytes per sector (paper: block 1 KB, sector 128 B)


def _h(tag: bytes, data: bytes) -> int:
    return int.from_bytes(hashlib.sha256(tag + data).digest(), "big")


def H3(data: bytes) -> int:
    return _h(b"H3", data) % R or 1


def H4(data: bytes):
    """Hash to G1 by try-and-increment (BN254: y^2 = x^3 + 3, p = 3 mod 4)."""
    ctr = 0
    while True:
        x = _h(b"H4" + ctr.to_bytes(4, "big"), data) % P
        rhs = (pow(x, 3, P) + int(CURVE_B.n)) % P
        y = pow(rhs, (P + 1) // 4, P)
        if y * y % P == rhs:
            return (FQ(x), FQ(y), FQ(1))
        ctr += 1


def pi(i: int, seed: int, mod: int) -> int:
    return _h(b"pi", i.to_bytes(8, "big") + seed.to_bytes(32, "big")) % mod


def sectors(block: bytes, s: int) -> list[int]:
    block = block.ljust(s * SECTOR, b"\x00")[:s * SECTOR]
    return [int.from_bytes(block[j * SECTOR:(j + 1) * SECTOR], "big") % R for j in range(s)]


@dataclass
class FileKeys:
    kl: bytes
    x: int
    s_a: int
    pk: tuple


class ZhangAudit:
    def __init__(self, s: int = 8):
        self.s = s
        self.chi = H4(b"chi")
        self.blocks: dict[int, list[bytes]] = {}      # epoch file -> ciphertext blocks (CSP)
        self.tags: dict[int, list[tuple]] = {}         # epoch file -> tau_i (CSP)
        self.keys: dict[int, FileKeys] = {}            # owner's keys; ak and pk shared as in the paper

    def upload(self, f: int, blocks: list[bytes]) -> None:
        kl = os.urandom(32)
        x, s_a = (int.from_bytes(os.urandom(32), "big") % R or 1 for _ in range(2))
        hk = H3(kl)
        pk = multiply(G2, hk * s_a % R)
        tags = []
        for i, c in enumerate(blocks):                                         # eq. 1
            base = add(H4(c + i.to_bytes(8, "big")), multiply(self.chi, sum(sectors(c, self.s)) % R))
            tags.append(multiply(base, hk))
        self.blocks[f], self.tags[f], self.keys[f] = list(blocks), tags, FileKeys(kl, x, s_a, pk)

    def challenge(self, f: int, l2: int, chain_seed: bytes) -> tuple[int, int, int]:
        """r3 = H1(t || num(t)), r4 = H1(t || nonce(t)) from the chain (modelled by a seed)."""
        return _h(b"r3", chain_seed) % R, _h(b"r4", chain_seed) % R, l2

    def prove(self, f: int, chal: tuple[int, int, int]):
        r3, r4, l2 = chal
        k = self.keys[f]
        blocks, tags, n = self.blocks[f], self.tags[f], len(self.tags[f])
        p = [0] * self.s
        psi, gamma = Z1, Z1
        for i in range(l2):                                                      # eq. 7
            a, b = pi(i, r3, n), pi(i, r4, R)
            c = blocks[a] if a < len(blocks) else b""
            for j, cj in enumerate(sectors(c, self.s)):
                p[j] = (p[j] + k.x * b * cj) % R
            psi = add(psi, multiply(tags[a], b))
            gamma = add(gamma, multiply(H4(c + a.to_bytes(8, "big")), b))
        return multiply(gamma, k.x), multiply(psi, k.s_a * k.x % R), p

    def verify(self, f: int, proof) -> bool:
        gamma, psi, p = proof                                                    # eq. 8
        theta = sum(p) % R
        lhs = pairing(self.keys[f].pk, add(gamma, multiply(self.chi, theta)))
        return lhs == pairing(G2, psi)

    def audit(self, f: int, l2: int, chain_seed: bytes) -> bool:
        return self.verify(f, self.prove(f, self.challenge(f, l2, chain_seed)))


def detection_probability(n: int, corrupted: int, l2: int) -> float:
    """Probability that l2 sampled blocks (with replacement, as pi1 is a PRF) hit at least one
    of `corrupted` blocks out of n."""
    return 1.0 - (1.0 - corrupted / n) ** l2


# Section VII-A, CSP cost of one audit: l2 (2 t_r + 2 t_x + t_a + t_z + 2 t_g + t_h) + 2 t_z + 2 t_x;
# verification by the smart contract: 2 pairings, 1 G1 exponentiation and multiplication, s additions.
def audit_cost_us(l2: int, s: int, u: dict[str, float]) -> dict[str, float]:
    csp = l2 * (2 * u["t_r"] + 2 * u["t_x"] + u["t_a"] + u["t_z"] + 2 * u["t_g"] + u["t_h"]) + 2 * u["t_z"] + 2 * u["t_x"]
    contract = 2 * u["t_b"] + u["t_x"] + u["t_g"] + s * u["t_a"]
    return dict(csp_us=csp, verify_us=contract)


def tag_cost_us(n: int, u: dict[str, float]) -> float:
    """Initial upload: n (2 t_h + t_g + 2 t_x + s t_a) + 3 t_x + t_a + t_g + 3 t_c (Section VII-A)."""
    return n * (2 * u["t_h"] + u["t_g"] + 2 * u["t_x"]) + 3 * u["t_x"] + u["t_g"]
