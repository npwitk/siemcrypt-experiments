"""Merkle Mountain Range with domain separation and multiproofs (Phase 2, Phase 6).

Hashing (Phase 2, Step 2):
  leaf      H(0x00 || data)                       (data = <rid, H(L~), H(I)>, eq:mmr-leaf)
  internal  H(0x01 || left || right)
  bagging   peaks combined right to left as H(0x02 || peak || acc)

Node (h, j) is the root of the perfect subtree over leaves [j*2^h, (j+1)*2^h); it exists
iff (j+1)*2^h <= n. Appending a leaf costs one leaf hash plus amortized one internal hash.

A multiproof (eq:mmr-multiproof) is the set of nodes needed, beyond the requested leaves,
to recompute the root; shared authentication nodes appear once.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .primitives import H

LEAF, NODE, PEAK = b"\x00", b"\x01", b"\x02"

Pos = tuple[int, int]  # (height, index within level)


class HashCounter:
    """Counts hash evaluations, used by the cost experiments."""

    def __init__(self) -> None:
        self.count = 0

    def __call__(self, data: bytes) -> bytes:
        self.count += 1
        return H(data)


def leaf_hash(data: bytes, h=H) -> bytes:
    return h(LEAF + data)


def _node(left: bytes, right: bytes, h=H) -> bytes:
    return h(NODE + left + right)


def _mountains(n: int) -> list[tuple[int, int]]:
    """(height, first leaf) of each perfect subtree, left to right."""
    out, start = [], 0
    for height in range(n.bit_length() - 1, -1, -1):
        if n >> height & 1:
            out.append((height, start))
            start += 1 << height
    return out


def _bag(peaks: list[bytes], h=H) -> bytes:
    acc = peaks[-1]
    for p in reversed(peaks[:-1]):
        acc = h(PEAK + p + acc)
    return acc


@dataclass
class MMR:
    levels: list[list[bytes]] = field(default_factory=lambda: [[]])
    hasher: object = H

    @property
    def size(self) -> int:
        return len(self.levels[0])

    def append_leaf_hash(self, lh: bytes) -> int:
        """Append an already-hashed leaf; returns its leaf index iota."""
        idx = self.size
        self.levels[0].append(lh)
        height = 0
        while len(self.levels[height]) % 2 == 0:
            lvl = self.levels[height]
            parent = _node(lvl[-2], lvl[-1], self.hasher)
            if len(self.levels) == height + 1:
                self.levels.append([])
            self.levels[height + 1].append(parent)
            height += 1
        return idx

    def append(self, data: bytes) -> int:
        return self.append_leaf_hash(leaf_hash(data, self.hasher))

    def node(self, pos: Pos) -> bytes:
        return self.levels[pos[0]][pos[1]]

    def peaks(self) -> list[bytes]:
        return [self.levels[h][s >> h] for h, s in _mountains(self.size)]

    def root(self) -> bytes:
        """R_e^MMR = MMR.Root(m_1, ..., m_n), eq:mmr-root."""
        if self.size == 0:
            return H(b"empty")
        return _bag(self.peaks(), self.hasher)

    def multiprove(self, indices: set[int] | list[int]) -> dict[Pos, bytes]:
        """MMR.MultiProve: nodes needed to recompute the root from the given leaves."""
        n = self.size
        wanted = set(indices)
        if not wanted or max(wanted) >= n or min(wanted) < 0:
            raise ValueError("leaf indices out of range")
        proof: dict[Pos, bytes] = {}
        for height, start in _mountains(n):
            known = {(0, i) for i in wanted if start <= i < start + (1 << height)}
            if not known:
                proof[(height, start >> height)] = self.node((height, start >> height))
                continue
            for h in range(height):
                parents = set()
                for (_, j) in sorted(p for p in known if p[0] == h):
                    sib = (h, j ^ 1)
                    if sib not in known:
                        proof[sib] = self.node(sib)
                    parents.add((h + 1, j >> 1))
                known |= parents
        return proof


def multiverify(
    leaves: dict[int, bytes], proof: dict[Pos, bytes], root: bytes, n: int, h=H
) -> bool:
    """MMR.MultiVerify(Lambda, MP, R, n), eq:mmr-multiverify.

    ``leaves`` maps leaf index iota to its leaf hash m_i (already domain-separated).
    """
    if n <= 0 or not leaves or max(leaves) >= n or min(leaves) < 0:
        return False
    known: dict[Pos, bytes] = {(0, i): v for i, v in leaves.items()}
    peaks: list[bytes] = []
    for height, start in _mountains(n):
        top = (height, start >> height)
        in_range = [i for i in leaves if start <= i < start + (1 << height)]
        if not in_range:
            if top not in proof:
                return False
            peaks.append(proof[top])
            continue
        for lvl in range(height):
            for (_, j) in sorted(p for p in list(known) if p[0] == lvl and _within(p, height, start)):
                if j % 2 == 1 and (lvl, j - 1) in known:
                    continue  # already combined from the left sibling
                sib = (lvl, j ^ 1)
                sib_hash = known.get(sib, proof.get(sib))
                if sib_hash is None:
                    return False
                left, right = (known[(lvl, j)], sib_hash) if j % 2 == 0 else (sib_hash, known[(lvl, j)])
                known[(lvl + 1, j >> 1)] = _node(left, right, h)
        peaks.append(known[top])
    return _bag(peaks, h) == root


def _within(pos: Pos, height: int, start: int) -> bool:
    lvl, j = pos
    lo = j << lvl
    return start <= lo < start + (1 << height)


def proof_size(proof: dict[Pos, bytes]) -> int:
    """Number of hashes in a (multi)proof."""
    return len(proof)
