"""Count-Min sketch [ref44] for the label-free screening path (Phase 5, Step 6).

The EE keeps a current-bucket sketch and a decayed baseline sketch with identical
dimensions and hash seeds, so they can be combined element-wise (eq:sketch-decay).
"""

from __future__ import annotations

import hashlib
import math

import numpy as np


class CountMin:
    def __init__(self, width: int, depth: int, seed: bytes = b"siemcrypt-cms"):
        self.w, self.d = width, depth
        self.seed = seed
        self.table = np.zeros((depth, width), dtype=np.float64)

    @classmethod
    def for_error(cls, eps: float, delta: float, seed: bytes = b"siemcrypt-cms") -> "CountMin":
        """w = ceil(e/eps), d = ceil(ln(1/delta)) gives error <= eps*N w.p. >= 1-delta."""
        return cls(math.ceil(math.e / eps), math.ceil(math.log(1 / delta)), seed)

    def like(self) -> "CountMin":
        """Empty sketch with the same dimensions and hash functions."""
        return CountMin(self.w, self.d, self.seed)

    def _cols(self, key: bytes) -> list[int]:
        digest = hashlib.blake2b(key, digest_size=8 * self.d, key=self.seed[:64]).digest()
        return [int.from_bytes(digest[8 * r : 8 * r + 8], "big") % self.w for r in range(self.d)]

    def update(self, key: bytes, inc: float = 1.0) -> None:
        for r, c in enumerate(self._cols(key)):
            self.table[r, c] += inc

    def query(self, key: bytes) -> float:
        return float(min(self.table[r, c] for r, c in enumerate(self._cols(key))))

    def decay_into(self, current: "CountMin", rho: float) -> None:
        """self <- rho * self + (1 - rho) * current, eq:sketch-decay."""
        if current.table.shape != self.table.shape or current.seed != self.seed:
            raise ValueError("sketches must share dimensions and seeds")
        self.table *= rho
        self.table += (1.0 - rho) * current.table

    def clear(self) -> None:
        self.table.fill(0.0)
