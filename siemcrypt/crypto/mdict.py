"""Authenticated dictionary for the EPII (journal Phase 2, eq:index-root).

A binary Merkle tree over the (key, value) pairs sorted by key. Keys are the encoded
posting keys <d, T> (and <B, b> for temporal postings); values are posting digests
D_d[T] (eq:posting-digest). Sorting makes non-membership provable: an absent key lies
strictly between two adjacent leaves, or before the first or after the last one.

Hashing (domain-separated from the MMR's 0x00-0x02):
  leaf      H(0x03 || <key, value>)
  internal  H(0x04 || left || right); an unpaired last node is promoted unchanged
  root      R^IDX = H(0x05 || <n> || top)          (n = number of leaves)

A proof for a set of keys is one multiproof: the leaves that witness membership or
non-membership of each key, plus the authentication nodes shared by all of them.
"""

from __future__ import annotations

from bisect import bisect_left
from dataclasses import dataclass, field

from .encoding import encode
from .primitives import H

LEAF, NODE, ROOT = b"\x03", b"\x04", b"\x05"

Pos = tuple[int, int]  # (height, index within level)


def _level_sizes(n: int) -> list[int]:
    sizes = [n]
    while sizes[-1] > 1:
        sizes.append((sizes[-1] + 1) // 2)
    return sizes


def _root(n: int, top: bytes | None, h=H) -> bytes:
    return h(ROOT + encode(n) + (top or b""))


@dataclass
class DictProof:
    n: int
    entries: dict[int, tuple[bytes, bytes]] = field(default_factory=dict)  # leaf index -> (key, value)
    nodes: dict[Pos, bytes] = field(default_factory=dict)

    def size(self) -> int:
        """Number of hashes in the proof (authentication nodes; leaves travel as data)."""
        return len(self.nodes)


class MerkleDict:
    def __init__(self, items: dict[bytes, bytes], hasher=H):
        self.h = hasher
        self.keys = sorted(items)
        self.values = [items[k] for k in self.keys]
        self.levels: list[list[bytes]] = [[hasher(LEAF + encode(k, v)) for k, v in zip(self.keys, self.values)]]
        while len(self.levels[-1]) > 1:
            lvl = self.levels[-1]
            self.levels.append([hasher(NODE + lvl[j] + lvl[j + 1]) if j + 1 < len(lvl) else lvl[j]
                                for j in range(0, len(lvl), 2)])

    @property
    def n(self) -> int:
        return len(self.keys)

    def root(self) -> bytes:
        return _root(self.n, self.levels[-1][0] if self.n else None, self.h)

    def get(self, key: bytes) -> bytes | None:
        i = bisect_left(self.keys, key)
        return self.values[i] if i < self.n and self.keys[i] == key else None

    def _witnesses(self, key: bytes) -> list[int]:
        """Leaf indices proving membership (one leaf) or non-membership (the neighbours)."""
        if not self.n:
            return []
        i = bisect_left(self.keys, key)
        if i < self.n and self.keys[i] == key:
            return [i]
        return [j for j in (i - 1, i) if 0 <= j < self.n]

    def prove(self, keys) -> DictProof:
        idx = sorted({j for k in keys for j in self._witnesses(k)})
        proof = DictProof(self.n, {i: (self.keys[i], self.values[i]) for i in idx})
        known = set(idx)
        for height, size in enumerate(_level_sizes(self.n)[:-1]):
            parents = set()
            for j in sorted(known):
                sib = j ^ 1
                if sib < size and sib not in known:
                    proof.nodes[(height, sib)] = self.levels[height][sib]
                parents.add(j >> 1)
            known = parents
        return proof


def verify(root: bytes, keys, proof: DictProof, h=H) -> dict[bytes, bytes | None] | None:
    """VerifyIDX: returns key -> value (None for a proven absent key), or None on failure."""
    n = proof.n
    if any(not 0 <= i < n for i in proof.entries):
        return None
    if n == 0:
        return {k: None for k in keys} if root == _root(0, None, h) and not proof.entries else None
    if not proof.entries:
        return None
    # recompute the root from the supplied leaves and authentication nodes
    known = {i: h(LEAF + encode(k, v)) for i, (k, v) in proof.entries.items()}
    for height, size in enumerate(_level_sizes(n)[:-1]):
        nxt = {}
        for j in sorted(known):
            if j % 2 == 1 and (j - 1) in known:
                continue  # combined with its left sibling
            sib = j ^ 1
            if sib >= size:
                nxt[j >> 1] = known[j]  # promoted
                continue
            sh = known.get(sib, proof.nodes.get((height, sib)))
            if sh is None:
                return None
            left, right = (known[j], sh) if j % 2 == 0 else (sh, known[j])
            nxt[j >> 1] = h(NODE + left + right)
        known = nxt
    if _root(n, known.get(0), h) != root:
        return None
    # leaves must be in strictly increasing key order
    order = sorted(proof.entries)
    if any(proof.entries[a][0] >= proof.entries[b][0] for a, b in zip(order, order[1:])):
        return None
    by_key = {k: v for k, v in proof.entries.values()}
    out = {}
    for k in keys:
        if k in by_key:
            out[k] = by_key[k]
            continue
        lo = max((i for i in order if proof.entries[i][0] < k), default=None)
        hi = min((i for i in order if proof.entries[i][0] > k), default=None)
        if lo is None and hi == 0 or hi is None and lo == n - 1 or (
                lo is not None and hi is not None and hi == lo + 1):
            out[k] = None
        else:
            return None
    return out
