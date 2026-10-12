"""B7: EVSEB, verifiable searchable encryption with Boolean search over encrypted cloud logs
(Fugkeaw, Deevijit, Ueasathitwong, Thanyasukpaisal, IEEE Access 13, 2025).

Reimplemented from Section IV-D:
  Phase 1  keys K_enc, K_index, K_auth, K_search (eq. 3); access tokens
           Token_u = Enc_AES(u || P_u || T_exp, K_auth) (eq. 4, 7); policies on chain (eq. 5-6)
  Phase 2  tree: root -> source -> log type; each leaf node holds a Bloom filter and an
           inverted index PRF(h(w)) -> {L_ID} (eq. 8-10, Algorithm 1)
  Phase 3  each log entry and its metadata encrypted with AES under K_enc (eq. 14-15)
  Phase 4  keywords inserted as PRF_K(w) = HMAC-SHA256(K_search, SHA-256(w)) into the node's
           inverted index and Bloom filter (Algorithm 2); the index encrypted under K_index (eq. 17)
  Phase 5  trapdoor T_w = HMAC-SHA256(K_search, SHA-256(w)) (eq. 18-19)
  Phase 6  VerifyAccess (eq. 21), node location, Bloom check (eq. 23), inverted-index lookup
           (eq. 24), AND / OR / NOT on pointer lists (eq. 25-27, Algorithm 3), then integrity:
           DHT[H(L_ID)] = h_LID = H(Enc(L_n)) (eq. 28); a quaternary Merkle tree over the DHT
           hashes, root on chain (Theorem 2); verification recomputes the root with the
           returned entries rehashed and, on mismatch, TraceTamperedNode descends the
           affected branches (Algorithms 4.1, 4.2)

Modelling choices (not fixed by the paper): keywords are the event's user, resource,
category and source, prefixed by their field, so EVSEB indexes what SIEMCrypt tokenizes;
one quaternary Merkle tree and on-chain root per epoch; the encrypted index is stored per
node and the search engine (which holds K_index) decrypts the target node per query.
Search tokens are deterministic and never rotate: the cloud sees the same trapdoor for a
keyword in every query (leakage L_Trapdoor, "keyword repetition pattern").
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from ..crypto.encoding import encode
from ..crypto.primitives import H, aead_decrypt, aead_encrypt, prf
from ..model import Event

ARITY = 4  # quaternary Merkle tree (Theorem 2 proof)


def keywords(ev: Event) -> list[str]:
    return [f"u:{ev.user}", f"r:{ev.res}", f"c:{ev.cat}", f"s:{ev.src}"]


class Bloom:
    """m-bit Bloom filter with k positions from one SHA-256 of the (pseudorandom) key."""

    def __init__(self, m: int = 1 << 16, k: int = 7):
        self.m, self.k, self.bits = m, k, bytearray(m // 8)

    def _pos(self, x: bytes):
        d = hashlib.sha256(x).digest()
        for i in range(self.k):
            yield int.from_bytes(d[4 * i:4 * i + 4], "big") % self.m

    def add(self, x: bytes) -> None:
        for p in self._pos(x):
            self.bits[p >> 3] |= 1 << (p & 7)

    def __contains__(self, x: bytes) -> bool:
        return all(self.bits[p >> 3] >> (p & 7) & 1 for p in self._pos(x))


@dataclass
class Node:
    bloom: Bloom = field(default_factory=Bloom)
    inv: dict[bytes, set[int]] = field(default_factory=lambda: defaultdict(set))
    blob: tuple[bytes, bytes] | None = None  # Enc(inverted index, K_index), eq. 17


def quad_tree(leaves: list[bytes], h=H) -> list[list[bytes]]:
    """Levels of a quaternary Merkle tree, leaves first; parents hash their (up to) four children."""
    levels = [list(leaves)]
    while len(levels[-1]) > 1:
        cur = levels[-1]
        levels.append([h(b"".join(cur[i:i + ARITY])) for i in range(0, len(cur), ARITY)])
    return levels


class EVSEB:
    def __init__(self):
        self.k_enc, self.k_index, self.k_auth, self.k_search = (os.urandom(32) for _ in range(4))  # eq. 3
        self.tree: dict[tuple[str, str], Node] = {}       # (source, log type) -> leaf node
        self.store: dict[int, tuple] = {}                 # L_ID -> (epoch, iv, ct, meta_iv, meta_ct)
        self.dht: dict[bytes, bytes] = {}                 # H(L_ID) -> h_LID (eq. 28)
        self.stored_tree: dict[int, list[list[bytes]]] = {}
        self.chain: dict[int, bytes] = {}                 # epoch -> Merkle root (on chain)
        self.epoch_ids: dict[int, list[int]] = defaultdict(list)
        self.policies: dict[str, bytes] = {}
        self.next_id = 0
        self.hashes = 0
        self.ops = Counter()
        self.t = Counter()
        self.view: list[tuple] = []                       # cloud's view of queries (trapdoor, |result|)

    def _h(self, data: bytes) -> bytes:
        self.hashes += 1
        return H(data)

    # ---------------------------------------------------------------- Phase 1
    def register(self, user: str, permissions: frozenset[str], ttl: float = 1e9) -> tuple[bytes, bytes]:
        """Policy on chain (eq. 5-6) and access token Token_u (eq. 7)."""
        texp = time.time() + ttl
        policy = json.dumps([H(user.encode()).hex(), sorted(permissions), texp]).encode()
        self.policies[user] = aead_encrypt(self.k_index, policy, b"policy")
        return aead_encrypt(self.k_auth, json.dumps([user, sorted(permissions), texp]).encode(), b"token")

    def verify_access(self, token: tuple[bytes, bytes], ltype: str) -> bool:
        """VerifyAccess(Token_u, L_Type) (eq. 21), a smart contract modelled as a local call."""
        self.ops["aes"] += 1
        _, perms, texp = json.loads(aead_decrypt(self.k_auth, *token, b"token"))
        return texp > time.time() and (ltype in perms or "*" in perms)

    # ---------------------------------------------------------------- Phases 3-4
    def trapdoor(self, w: str) -> bytes:                                           # eq. 18-19
        self.ops["prf"] += 1
        self.hashes += 1
        return prf(self.k_search, H(w.encode()))

    def ingest_epoch(self, epoch: int, events: list[Event]) -> None:
        t0 = time.perf_counter()
        for ev in events:
            lid = self.next_id
            self.next_id += 1
            iv, ct = aead_encrypt(self.k_enc, ev.payload, b"log")                   # eq. 14
            miv, mct = aead_encrypt(self.k_enc, encode(repr(ev.ts), ev.src, ev.cat), b"meta")  # eq. 15
            self.ops["aes"] += 2
            self.store[lid] = (epoch, iv, ct, miv, mct)
            node = self.tree.setdefault((ev.src, ev.cat), Node())
            for w in keywords(ev):                                                 # Algorithm 2
                tw = self.trapdoor(w)
                node.inv[tw].add(lid)
                node.bloom.add(tw)
            self.dht[self._h(encode(lid))] = self._h(ct)                           # eq. 28
            self.epoch_ids[epoch].append(lid)
        levels = quad_tree([self.dht[H(encode(lid))] for lid in self.epoch_ids[epoch]], self._h)
        self.stored_tree[epoch] = levels
        self.chain[epoch] = levels[-1][0]                                          # on-chain root
        for node in self.tree.values():                                            # eq. 17
            blob = json.dumps({k.hex(): sorted(v) for k, v in node.inv.items()}).encode()
            node.blob = aead_encrypt(self.k_index, blob, b"index")
            self.ops["aes"] += 1
        self.t["ingest"] += time.perf_counter() - t0

    # ---------------------------------------------------------------- Phase 6
    def _lookup(self, ltype_nodes, tw) -> set[int]:
        out = set()
        for node in ltype_nodes:
            if tw in node.bloom:                                                   # eq. 23
                out |= node.inv.get(tw, set())                                     # eq. 24
        return out

    def search(self, words: list[str], op: str = "AND", token=None, ltype: str | None = None) -> set[int]:
        t0 = time.perf_counter()
        if token is not None and not self.verify_access(token, ltype or "*"):
            return set()
        nodes = [n for (src, cat), n in self.tree.items() if ltype is None or cat == ltype]
        for n in nodes:                                                            # decrypt node index
            aead_decrypt(self.k_index, *n.blob, b"index")
            self.ops["aes"] += 1
        lists = []
        for w in words:
            tw = self.trapdoor(w)
            res = self._lookup(nodes, tw)
            self.view.append((tw, len(res)))
            lists.append(res)
        if op == "AND":
            out = set.intersection(*lists)                                         # eq. 25
        elif op == "OR":
            out = set.union(*lists)                                                # eq. 26
        else:
            out = set(self.store) - lists[0]                                       # eq. 27
        self.t["search"] += time.perf_counter() - t0
        return out

    def verify(self, lids: set[int]) -> tuple[set[int], set[int]]:
        """Algorithm 4.1: returns (verified, tampered). Recomputes each affected epoch's root
        with the returned entries rehashed from storage and the rest taken from the DHT."""
        t0 = time.perf_counter()
        tampered = set()
        by_ep = defaultdict(set)
        for lid in lids:
            by_ep[self.store[lid][0] if lid in self.store else None].add(lid)
        for e, sel in by_ep.items():
            if e is None:
                tampered |= sel
                continue
            ids = self.epoch_ids[e]
            leaves = []
            for lid in ids:
                if lid in sel:
                    rec = self.store.get(lid)
                    leaves.append(self._h(rec[2]) if rec else b"")
                else:
                    leaves.append(self.dht.get(H(encode(lid)), b""))
            recomputed = quad_tree(leaves, self._h)
            if recomputed[-1][0] != self.chain[e]:
                tampered |= {ids[i] for i in self._trace(self.stored_tree[e], recomputed)} & sel or sel
        self.t["verify"] += time.perf_counter() - t0
        return lids - tampered, tampered

    @staticmethod
    def _trace(stored, recomputed) -> list[int]:
        """Algorithm 4.2: descend only into children whose hashes differ."""
        affected = [0]
        for lvl in range(len(stored) - 1, 0, -1):
            nxt = []
            for node in affected:
                for c in range(node * ARITY, min((node + 1) * ARITY, len(recomputed[lvl - 1]))):
                    if c >= len(stored[lvl - 1]) or recomputed[lvl - 1][c] != stored[lvl - 1][c]:
                        nxt.append(c)
            affected = nxt
        return affected
