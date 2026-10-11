"""Injective encodings.

- ``encode``: the length-prefixed encoding <.> used inside MMR leaves (eq:mmr-leaf).
- ``FixedPoint``: fixed-point encoding of real-valued HE features, floor(2^f x) mod N
  with centered decoding from (-N/2, N/2) (Phase 1, Step 3).
"""

from __future__ import annotations

import struct

Field = bytes | str | int


def _to_bytes(x: Field) -> bytes:
    if isinstance(x, bytes):
        return b"b" + x
    if isinstance(x, str):
        return b"s" + x.encode()
    if isinstance(x, int):
        sign = b"-" if x < 0 else b"+"
        mag = abs(x)
        return b"i" + sign + mag.to_bytes(max(1, (mag.bit_length() + 7) // 8), "big")
    raise TypeError(f"unsupported field type {type(x)!r}")


def encode(*fields: Field) -> bytes:
    """Length-prefixed, type-tagged concatenation; distinct inputs give distinct outputs."""
    out = bytearray(struct.pack(">I", len(fields)))
    for f in fields:
        b = _to_bytes(f)
        out += struct.pack(">I", len(b)) + b
    return bytes(out)


class FixedPoint:
    """Encode reals as integers mod N with a public precision of ``frac_bits`` bits."""

    def __init__(self, modulus: int, frac_bits: int = 16):
        self.n = modulus
        self.f = frac_bits
        self.scale = 1 << frac_bits

    def encode(self, x: float | int) -> int:
        v = round(x * self.scale)
        if abs(v) >= self.n // 2:
            raise OverflowError("value exceeds the centered plaintext range")
        return v % self.n

    def encode_weight(self, w: float | int) -> int:
        """Integer weight for ciphertext-plaintext multiplication (no scaling for integers)."""
        if isinstance(w, int):
            return w % self.n
        return round(w * self.scale) % self.n

    def decode_int(self, v: int) -> int:
        v %= self.n
        return v - self.n if v > self.n // 2 else v

    def decode(self, v: int, weight_scaled: bool = False) -> float:
        """Decode a sum of encoded values; pass weight_scaled if a real weight was applied."""
        s = self.scale * (self.scale if weight_scaled else 1)
        return self.decode_int(v) / s
