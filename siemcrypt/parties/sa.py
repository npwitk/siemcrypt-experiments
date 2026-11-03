"""Security Analyst (SA): MMR-bound batch-verifiable investigation (Phase 6).

Step 1  window from the alert's adaptive horizon (eq:investigation-window) or default.
Step 2  historical expansion via EE-derived tokens (eq:investigation-reference-set).
Step 4  checkpoint signature (eq:batch-checkpoint-verification), chain
        (journal eq:checkpoint-linkage: h_{tau-1}^CP = H(CP_{tau-1})), multiproof
        (eq:mmr-multiverify) -> verified set. With cfg.acl (journal dual authentication) the
        historical query results are first verified against R_tau^IDX and the reference set
        is recomputed from the authenticated postings
        (eq:investigation-index-verification).
Step 5  payload key from the KA only for verified epochs; decrypt; drop decoys
        (eq:payload-recovery, eq:decoy-filter).
Step 6  identity resolution through the TD (eq:identity-resolution).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from .. import lineage
from ..bus import Bus
from ..crypto.encoding import encode
from ..crypto.mmr import leaf_hash, multiverify
from ..crypto.primitives import H, AeadError, aead_decrypt, verify
from ..protocol import aead_ad, leaf_data
from .ee import Descriptor


@dataclass
class Investigation:
    descriptor: Descriptor
    window: range
    verified_epochs: list[int] = field(default_factory=list)
    failed_epochs: list[int] = field(default_factory=list)
    verified_records: int = 0
    tampered_records: int = 0
    missing_records: int = 0
    decoys_dropped: int = 0
    plaintexts: list[bytes] = field(default_factory=list)
    identity: str | None = None
    index_failed_epochs: list[int] = field(default_factory=list)
    timing: dict = field(default_factory=dict)  # seconds: epii, checkpoint, mmr, c_inv
    refs: set = field(default_factory=set)
    evidence: dict = field(default_factory=dict)
    c_inv: bytes | None = None


class SecurityAnalyst:
    def __init__(self, bus: Bus, default_lookback: int, acl: bool = False):
        self.bus = bus
        self.acl = acl
        self.alerts: list[Descriptor] = []
        self.default_lookback = default_lookback
        self.ee = self.cloud = self.ka = self.td = None  # wired by the system

    def receive_alert(self, d: Descriptor) -> None:
        self.alerts.append(d)

    def investigate(self, d: Descriptor, span: int | None = None, full_history: bool = False) -> Investigation:
        """span: explicit window length (journal v2 Exp 6 sweep); full_history: Full-History
        baseline, every epoch since the first and every record of the entity (no profile scope)."""
        e = d.epoch
        if span is None:
            span = d.horizon if d.horizon is not None else self.default_lookback
        if full_history:
            span = e
        window = range(max(1, e - span + 1), e + 1)
        inv = Investigation(d, window)

        # Step 2: the EE resolves the current token internally and derives historical queries
        user = self.ee.resolve_current(e, d.token)
        queries = self.ee.investigation_queries(user, None if full_history else d.attack, window)
        refs = {rid for rid in d.provenance if rid[0] in window}  # lineage refs inside the window
        answers = {}
        for tau, tok in queries.items():
            if self.acl:
                answers[tau] = self.bus.send("cloud", "sa", "inv_answer", self.cloud.inv_query_auth(tau, tok))
                refs |= answers[tau][0]
            else:
                refs |= self.cloud.inv_query(tau, tok)

        # Step 3: evidence packages with per-epoch multiproofs
        ev = self.cloud.evidence(refs, window)
        cps = ev["checkpoints"]

        # Step 4: checkpoint signature + chain, then multiproof
        t0 = time.perf_counter()
        cp_ok = {}
        for tau, (cp, sig) in cps.items():
            ok = cp[0] == tau and verify(self.ka.pk_ka, H(encode(*cp)), sig)
            prev = cps.get(tau - 1)
            if ok and prev is not None:
                ok = cp[3] == lineage.checkpoint_hash(prev[0])  # h_{tau-1}^CP == H(CP_{tau-1})
            cp_ok[tau] = ok
        inv.timing["checkpoint"] = time.perf_counter() - t0
        # dual authentication: the query results of every window epoch are bound to R_tau^IDX,
        # so omitted or substituted search results are detected (journal Theorem 3)
        t0 = time.perf_counter()
        bad_index = set()
        for tau, (Q, postings, proof) in answers.items():
            cp = cps.get(tau, (None,))[0]
            ok = cp is not None and cp_ok.get(tau) and lineage.verify_postings(cp[2], queries[tau], postings, proof)
            if ok:
                ok = {(tau, i) for i in lineage.candidates_from(queries[tau], postings, cp[4])} == Q
            if not ok:
                bad_index.add(tau)
        inv.index_failed_epochs = sorted(bad_index)
        inv.timing["epii"] = time.perf_counter() - t0
        # completeness w.r.t. the requested references (rid-addressed); without ACL, omission
        # from the search results themselves is not detectable by inclusion proofs
        returned = {rid for pkg in ev["packages"].values() for rid in pkg["records"]}
        missing = refs - returned
        inv.missing_records = len(missing)
        incomplete = {rid[0] for rid in missing} | bad_index
        inv.failed_epochs.extend(sorted(incomplete - set(ev["packages"])))
        verified = set()
        t0 = time.perf_counter()
        for tau, pkg in ev["packages"].items():
            cp, _ = pkg["checkpoint"]
            leaves = {rec.iota: leaf_hash(leaf_data(rec, ent)) for rec, ent in pkg["records"].values()}
            if tau not in incomplete and cp_ok.get(tau) and multiverify(leaves, pkg["proof"], cp[1], cp[4]):
                inv.verified_epochs.append(tau)
                verified |= set(pkg["records"])
            else:
                inv.failed_epochs.append(tau)
        inv.timing["mmr"] = time.perf_counter() - t0
        inv.verified_records = len(verified)
        inv.refs, inv.evidence = refs, ev
        if self.acl:
            t0 = time.perf_counter()
            inv.c_inv = lineage.c_inv(d.state_commitment, window, None if full_history else d.attack, refs,
                                      {tau: cp[0][1] for tau, cp in cps.items()}, verified)
            inv.timing["c_inv"] = time.perf_counter() - t0

        # Step 5: verify-before-decrypt
        identity_token = None
        for tau in inv.verified_epochs:
            key = self.bus.send("ka", "sa", "payload_key", self.ka.payload_key(tau, verified=True))
            for rid, (rec, ent) in ev["packages"][tau]["records"].items():
                try:
                    pt = aead_decrypt(key, rec.iv, rec.ct, aead_ad(tau, ent.bucket, rec.meta))
                except AeadError:
                    inv.tampered_records += 1
                    continue
                if pt[0] == 1:
                    inv.decoys_dropped += 1
                    continue
                inv.plaintexts.append(pt[1:])
                if ent.tokens[0] in queries.get(tau, {}).get("U", ()):
                    identity_token = (tau, ent.tokens[0])

        # Step 6: controlled identity resolution
        if identity_token is not None:
            self.bus.send("sa", "td", "resolve", identity_token)
            inv.identity = self.td.resolve(*identity_token)
        return inv
