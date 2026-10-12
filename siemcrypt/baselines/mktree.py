"""B8: MK-Tree, DHT-backed ancestor-assisted Merkle verification for log integrity
(Saengthong, Mantharngkul, Wongsuwan, Ritthaisong, Fugkeaw, IEEE OJ-CS 7, 2026).

Reimplemented from Section III:
  Phase 1  canonical record M, AEAD (c, t) <- Enc_K(M, AD) with AD = (log type, timestamp)
           (eq. 13-14); leaf digest d = H(0x00 || c || t || AD) (eq. 15); producer signature
           sigma = Sign(H(0xA3 || d)) (eq. 16)
  Phase 2  the storage verifier recomputes d and checks sigma before storing (eq. 18-19)
  Phase 3  per log type and epoch a binary Merkle tree, padded to a power of two with
           H(0x00 || 0) (eq. 2), internal nodes H(0x01 || left || right) (eq. 3, 21); parent node
           records P_jk and, at stride level s, ancestor certificates C_sk = (A_sk, upProof,
           [i_min, i_max], seq) in the DHT (eq. 4-6, 22-23); the root-of-roots
           R_agg = H(R_t1 || ... || R_tm) committed on chain (eq. 7-8, 24-25)
  Phase 4  inclusion and batch verification: leaves are recomputed up to their level-s
           ancestor, each distinct ancestor is checked once against its certificate up to
           R_t, and R_agg against the chain (eq. 9, 26-27); hash cost <= n(L - s) + g s
           (Theorem IV-G.1)

Not implemented: the CA-issued auditor tokens and the sliding-window micro-roots (Phase 5),
which change neither the verification work nor the detection results measured here.
"""

from __future__ import annotations

import time
from collections import Counter, defaultdict

from ..crypto.encoding import encode
from ..crypto.primitives import H, Signer, aead_encrypt, verify
from ..model import Event

TAG_L, TAG_I, TAG_SIG = b"\x00", b"\x01", b"\xa3"


class MKTree:
    def __init__(self, stride: int = 4):
        self.s = stride
        self.key = bytes(32)
        self.producer = Signer()
        self.store: dict[tuple, tuple] = {}            # (epoch, type, i) -> (iv, ct, ad, d, sigma)
        self.levels: dict[tuple, list[list[bytes]]] = {}  # (epoch, type) -> tree levels, root first
        self.certs: dict[tuple, tuple] = {}            # (epoch, type, k) -> (A_sk, upProof, range, seq)
        self.types: dict[int, list[str]] = defaultdict(list)
        self.chain: dict[int, bytes] = {}              # epoch -> R_agg
        self.seq = 0
        self.hashes = 0
        self.ops = Counter()
        self.t = Counter()

    def _h(self, data: bytes) -> bytes:
        self.hashes += 1
        return H(data)

    def _leaf(self, iv: bytes, ct: bytes, ad: bytes) -> bytes:
        return self._h(TAG_L + iv + ct + ad)                                     # eq. 15

    # ---------------------------------------------------------------- Phases 1-3
    def ingest_epoch(self, epoch: int, events: list[Event]) -> None:
        t0 = time.perf_counter()
        by_type = defaultdict(list)
        for ev in events:
            ad = encode(ev.cat, repr(ev.ts))                                      # AD = (type, timestamp)
            iv, ct = aead_encrypt(self.key, ev.payload, ad)                       # eq. 14
            d = self._leaf(iv, ct, ad)
            sigma = self.producer.sign(self._h(TAG_SIG + d))                      # eq. 16
            self.ops["sign"] += 1
            d2 = self._leaf(iv, ct, ad)                                           # eq. 18-19 (storage)
            assert verify(self.producer.pk, self._h(TAG_SIG + d2), sigma)
            self.ops["verify_sig"] += 1
            by_type[ev.cat].append((iv, ct, ad, d, sigma))
        roots = []
        for tau in sorted(by_type):
            recs = by_type[tau]
            for i, r in enumerate(recs):
                self.store[(epoch, tau, i)] = r
            leaves = [r[3] for r in recs]
            n = 1 << max(0, (len(leaves) - 1).bit_length())
            leaves += [self._h(TAG_L + b"\x00")] * (n - len(leaves))             # eq. 2 padding
            levels = [leaves]
            while len(levels[0]) > 1:
                cur = levels[0]
                levels.insert(0, [self._h(TAG_I + cur[2 * k] + cur[2 * k + 1]) for k in range(len(cur) // 2)])
            self.levels[(epoch, tau)] = levels                                    # P_jk in the DHT
            s = min(self.s, len(levels) - 1)
            for k, a in enumerate(levels[s]):                                     # eq. 4-5, 23
                up, idx = [], k
                for j in range(s, 0, -1):
                    up.append((idx & 1, levels[j][idx ^ 1]))
                    idx >>= 1
                span = 1 << (len(levels) - 1 - s)
                self.certs[(epoch, tau, k)] = (a, up, (k * span, (k + 1) * span - 1), self.seq)
                self.seq += 1
            roots.append(levels[0][0])
            self.types[epoch].append(tau)
        self.chain[epoch] = self._h(b"".join(roots))                              # eq. 7-8, 24-25
        self.t["ingest"] += time.perf_counter() - t0

    # ---------------------------------------------------------------- Phase 4
    def verify(self, refs: set[tuple]) -> tuple[set, set]:
        """Batch verification of records (epoch, type, i). Returns (verified, tampered)."""
        t0 = time.perf_counter()
        bad = set()
        by_tree = defaultdict(list)
        for ref in refs:
            by_tree[ref[:2]].append(ref)
        roots_ok = {}
        for (e, tau), sel in by_tree.items():
            levels = self.levels[(e, tau)]
            L = len(levels) - 1
            s = min(self.s, L)
            groups = defaultdict(list)
            for ref in sel:
                groups[ref[2] >> (L - s)].append(ref)
            for k, grp in groups.items():
                # bottom-up: recompute leaves and shared parents up to A_sk (P_jk from the DHT)
                cur = {}
                for ref in grp:
                    rec = self.store.get(ref)
                    d = self._leaf(*rec[:3]) if rec else b""
                    if rec and not verify(self.producer.pk, self._h(TAG_SIG + d), rec[4]):
                        d = b""
                    self.ops["verify_sig"] += 1
                    cur[ref[2]] = d
                for j in range(L, s, -1):
                    nxt = {}
                    for i, v in cur.items():
                        p = i >> 1
                        if p in nxt:
                            continue
                        left = cur.get(2 * p, levels[j][2 * p])
                        right = cur.get(2 * p + 1, levels[j][2 * p + 1])
                        nxt[p] = self._h(TAG_I + left + right)
                    cur = nxt
                a, up, _, _ = self.certs[(e, tau, k)]
                ok = cur[k] == a
                # top-down: certified ancestor to R_tau, once per ancestor
                x = a
                for bit, sib in up:
                    x = self._h(TAG_I + (sib + x if bit else x + sib))
                ok = ok and x == levels[0][0]
                if not ok:
                    bad |= set(grp)
            roots_ok[(e, tau)] = levels[0][0]
        for e in {k[0] for k in by_tree}:
            agg = self._h(b"".join(self.levels[(e, tau)][0][0] for tau in self.types[e]))
            if agg != self.chain[e]:
                bad |= {r for r in refs if r[0] == e}
        self.t["verify"] += time.perf_counter() - t0
        return set(refs) - bad, bad
