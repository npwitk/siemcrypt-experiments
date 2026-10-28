"""Authenticated EPII and Authenticated Computation Lineage (journal Phases 2-5).

Shared by the Cloud SIEM, which computes, and the EE and SA, which verify, so that both
sides evaluate exactly the same deterministic functions.

Phase 2  posting digest     D_d[T] = H(0x11 || <d, T, EncList(I_d[T])>)    eq:posting-digest
         index root         R_e^IDX = MerkleDict over (<d, T>, D_d[T])     eq:index-root
         (temporal postings <B, b> are included the same way)
Phase 3  C_chi = H(0x10 || H(Q) || R^MMR || R^IDX || H(CP_e))              eq:context-commitment
         C_Q   = H(0x12 || C_chi || H(EncList(Q_q)))                       eq:candidate-commitment
         C_A   = H(0x13 || C_Q || H(J_q) || H(A_q))                        eq:aggregate-commitment
         rho_q = H(0x14 || C_chi || C_Q || C_A)                            eq:acl-record
Phase 4  C_eps = H(0x20 || T_u || T_r || T_c || H(f) || H(EncList(R)))      eq:contracted-edge-commitment
         C_rho = H(0x21 || EncSet{rho_q})                                  eq:context-lineage-commitment
         C_G   = H(0x22 || T_u || a || H(EncSet{C_eps}) || H(g) || H(y) || C_rho)
Phase 5  C_H   = H(0x30 || C_H^(e-1) || C_in || H(h) || H(R) || H(EncSet(Prov)))
         with C_in = C_G for an active pair and H(inactive || e || a) otherwise (eq:cin-sec)

A_q contains the feature aggregates of J_q and the realness aggregate A_{q,0}, which the KA
release policy uses; this is the (|J_q| + 1) of the journal's ACL cost row.
"""

from __future__ import annotations

import math
from collections import defaultdict

from .crypto.encoding import encode
from .crypto.mdict import MerkleDict
from .crypto.primitives import H
from .model import GRAPH_FEATURES
from .protocol import DIMS

# ============================================================================ Phase 2
def posting_key(dim: str, key) -> bytes:
    return encode(dim, key)


def posting_digest(dim: str, key, iotas, h=H) -> bytes:
    return h(b"\x11" + encode(dim, key, *sorted(iotas)))


def postings_of(entries) -> dict[tuple[str, object], list[int]]:
    """(d, T) -> sorted leaf indices, and (B, b) -> leaf indices, for one epoch."""
    out = defaultdict(list)
    for ent in entries:
        for d, T in zip(DIMS, ent.tokens):
            out[(d, T)].append(ent.iota)
        out[("B", ent.bucket)].append(ent.iota)
    return {k: sorted(v) for k, v in out.items()}


def build_index(entries, h=H) -> MerkleDict:
    return MerkleDict({posting_key(d, k): posting_digest(d, k, v, h) for (d, k), v in postings_of(entries).items()}, h)


def query_keys(tokens: dict[str, frozenset]) -> list[tuple[str, bytes]]:
    return sorted((d, T) for d, toks in tokens.items() for T in toks)


def candidates_from(tokens: dict[str, frozenset], postings: dict, n: int) -> set[int]:
    """Q_q = intersection over specified dims of unions of posting lists (eq:candidate-set);
    the whole epoch when no dimension is specified."""
    if not tokens:
        return set(range(n))
    sets = []
    for d, toks in tokens.items():
        s = set()
        for T in toks:
            s.update(postings.get((d, T), ()))
        sets.append(s)
    return set.intersection(*sets)


def verify_postings(root: bytes, tokens: dict[str, frozenset], postings: dict, proof, h=H) -> bool:
    """VerifyIDX: every queried posting list is the one committed under R^IDX (an absent key
    must come with an empty list), and nothing else is supplied."""
    from .crypto.mdict import verify

    keys = query_keys(tokens)
    if set(postings) - set(keys):
        return False
    got = verify(root, [posting_key(d, T) for d, T in keys], proof, h)
    if got is None:
        return False
    for d, T in keys:
        D = got[posting_key(d, T)]
        lst = postings.get((d, T), ())
        if D is None:
            if lst:
                return False
        elif not lst or posting_digest(d, T, lst, h) != D:
            return False
    return True


# ============================================================================ Phase 3
def query_hash(q: dict) -> bytes:
    toks = [x for d in sorted(q["tokens"]) for x in (d, *sorted(q["tokens"][d]))]
    sw = [x for T in sorted(q["source_weights"]) for x in (T, int(q["source_weights"][T]))]
    return H(encode(q["qid"], q["attack"], q["epoch"], q["slot"], *toks, "|", *q["feats"], "|", *sw,
                    str(q["policy"].value), repr(q["threshold"])))


def checkpoint_hash(cp: tuple) -> bytes:
    return H(encode(*cp))


def c_chi(q: dict, cp: tuple, h=H) -> bytes:
    _, r_mmr, r_idx, _, _ = cp
    return h(b"\x10" + query_hash(q) + r_mmr + r_idx + checkpoint_hash(cp))


def c_q(chi: bytes, Q, h=H) -> bytes:
    return h(b"\x12" + chi + H(encode(*sorted(Q))))


def a_hash(aggs: dict, realness, feats) -> bytes:
    return H(encode(*[int(aggs[f]) for f in feats], int(realness)))


def c_spec(q: dict) -> bytes:
    """C_spec = H(Enc(J_q, vartheta_q)) (journal v2 eq:computation-specification): the features
    and every coefficient or parameter of the prescribed computation."""
    sw = [x for T in sorted(q["source_weights"]) for x in (T, int(q["source_weights"][T]))]
    return H(encode("spec", *q["feats"], "|", *sw, str(q["policy"].value), repr(q["threshold"])))


def c_a(cq: bytes, feats, aggs: dict, realness, h=H, spec: bytes | None = None) -> bytes:
    """C_A = H(0x13 || C_Q || C_spec || H(A_q)); without spec, C_spec covers J_q only (v1)."""
    return h(b"\x13" + cq + (spec if spec is not None else H(encode(*feats))) + a_hash(aggs, realness, feats))


def acl_record(chi: bytes, cq: bytes, ca: bytes, h=H, spec: bytes | None = None) -> bytes:
    """rho_q = H(0x14 || C_chi || C_Q || [C_spec ||] C_A) (journal v2 eq:acl-record)."""
    return h(b"\x14" + chi + cq + (spec or b"") + ca)


def aggregate(q: dict, Q, X_of, src_of, feat_index: dict, he, summer):
    """SG-HEF aggregates over the candidate set (eq:he-aggregation, eq:multisource-aggregate).
    X_of(rid) -> (X, X0); src_of(rid) -> source token; summer sums an iterable of ciphertexts."""
    aggs = {}
    for f in q["feats"]:
        j = feat_index[f]
        if q["source_weights"]:
            parts = []
            for Ts, w in q["source_weights"].items():
                parts.append(he.smul(summer(X_of(r)[0][j] for r in Q if src_of(r) == Ts), w))
            aggs[f] = summer(parts)
        else:
            aggs[f] = summer(X_of(r)[0][j] for r in Q)
    realness = summer(X_of(r)[1] for r in Q)
    return aggs, realness


# ============================================================================ Phase 4
def _f(x) -> str:
    return repr(float(x))


def contract(Z: list[dict], entry_of, profiles: dict[str, frozenset], h=H):
    """Attack-aware graph contraction (journal Phase 4) as a pure function of the accepted
    Phase 3 evidence Z and the index entries of the candidate records.

    Returns the updates (T_u, a, z, refs, C_G) and the token-independent epoch profile mu."""
    Qall = set().union(*(z["Q"] for z in Z)) if Z else set()
    rel = {}  # (T_U, T_R, T_C) -> [n, sources, bucket histogram, refs]
    for rid in Qall:
        tu, tr, tc, ts = entry_of(rid).tokens
        r = rel.setdefault((tu, tr, tc), [0, set(), defaultdict(int), set()])
        r[0] += 1
        r[1].add(ts)
        r[2][entry_of(rid).bucket] += 1
        r[3].add(rid)
    slots = defaultdict(list)
    for z in Z:
        slots[z["attack"]].append(z)
    updates = []
    for a, cat_tokens in profiles.items():
        by_entity = defaultdict(list)
        for k, v in rel.items():
            if k[2] in cat_tokens:  # eq:attack-projection
                by_entity[k[0]].append((k, v))
        for tu in sorted(by_entity):
            nbh = sorted(by_entity[tu], key=lambda kv: kv[0])
            srcs, buckets, res, refs = set(), set(), set(), set()
            deg, c_eps = 0, []
            for (_, tr, tc), (n, s, hist, rr) in nbh:
                deg += n
                srcs |= s
                buckets |= set(hist)
                res.add(tr)
                refs |= rr
                if h is not None:
                    f = encode(n, len(s), *[x for b in sorted(hist) for x in (b, hist[b])])
                    c_eps.append(h(b"\x20" + tu + tr + tc + H(f) + H(encode(*sorted(i for _, i in rr)))))
            g = [deg, len(res), len(srcs), len(nbh), len(buckets)]
            assert len(g) == len(GRAPH_FEATURES)
            # Fuse_{F_a}: one slot per context of class a; HIDE -> 0 (fixed dimension)
            y, rhos = [], []
            for z in slots[a]:
                hit = bool(z["Q"] & refs)
                y.append(sum(v for v in z["y"].values() if v is not None) if hit else 0.0)
                if hit and z.get("rho") is not None:
                    rhos.append(z["rho"])
            cg = None
            if h is not None:
                c_rho = h(b"\x21" + encode(*sorted(rhos)))
                cg = h(b"\x22" + tu + encode(a) + H(encode(*sorted(c_eps))) + H(encode(*map(_f, g)))
                       + H(encode(*map(_f, y))) + c_rho)
            updates.append((tu, a, g + y, frozenset(refs), cg))
    if rel:
        vals = list(rel.values())
        mu = [len(vals), sum(v[0] for v in vals) / len(vals),
              sum(len(v[1]) for v in vals) / len(vals), sum(len(v[2]) for v in vals) / len(vals)]
    else:
        mu = [0.0, 0.0, 0.0, 0.0]
    return updates, mu


def drift(mu, mu_prev) -> float:
    """D_e from consecutive epoch profiles (eq:environment-drift)."""
    if mu_prev is None:
        return 0.0
    num = math.sqrt(sum((a - b) ** 2 for a, b in zip(mu, mu_prev)))
    return num / (math.sqrt(sum(b * b for b in mu_prev)) + 1e-9)


# ============================================================================ Phase 5
def c_h(prev: bytes, c_in: bytes, hvec, R: float, prov, h=H) -> bytes:
    return h(b"\x30" + prev + c_in + H(encode(*map(_f, hvec))) + H(encode(_f(R)))
             + H(encode(*[x for rid in sorted(prov) for x in rid])))


def c_inactive(epoch: int, attack: str) -> bytes:
    return H(encode("inactive", epoch, attack))

