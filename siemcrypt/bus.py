"""Message bus between parties: counts bytes per (src, dst, kind) and records the
Cloud SIEM's complete view for the leakage experiments (E3)."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import gmpy2


def size_of(obj: Any, ct_bytes: int = 512) -> int:
    """Approximate serialized size in bytes."""
    if obj is None:
        return 1
    if isinstance(obj, (bytes, bytearray)):
        return len(obj)
    if isinstance(obj, str):
        return len(obj.encode())
    if isinstance(obj, bool):
        return 1
    if isinstance(obj, int):
        return 8
    if isinstance(obj, float):
        return 8
    if type(obj).__name__ == "mpz":
        return ct_bytes if gmpy2.mpz(obj).bit_length() > 64 else 8
    if isinstance(obj, dict):
        return sum(size_of(k, ct_bytes) + size_of(v, ct_bytes) for k, v in obj.items())
    if isinstance(obj, (list, tuple, set, frozenset)):
        return sum(size_of(x, ct_bytes) for x in obj)
    if hasattr(obj, "__dict__"):
        return size_of(vars(obj), ct_bytes)
    return 8


@dataclass
class Bus:
    ct_bytes: int = 512
    record_cloud_view: bool = True
    bytes: dict[tuple[str, str, str], int] = field(default_factory=lambda: defaultdict(int))
    count: dict[tuple[str, str, str], int] = field(default_factory=lambda: defaultdict(int))
    cloud_view: list[tuple[str, str, Any]] = field(default_factory=list)

    def send(self, src: str, dst: str, kind: str, obj: Any) -> Any:
        self.bytes[(src, dst, kind)] += size_of(obj, self.ct_bytes)
        self.count[(src, dst, kind)] += 1
        if self.record_cloud_view and dst == "cloud":
            self.cloud_view.append((src, kind, obj))
        return obj

    def total(self, src: str | None = None, dst: str | None = None) -> int:
        return sum(
            v for (s, d, _), v in self.bytes.items() if (src is None or s == src) and (dst is None or d == dst)
        )
