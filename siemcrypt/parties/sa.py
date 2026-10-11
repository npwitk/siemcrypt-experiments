"""Security Analyst (SA): MMR-bound batch-verifiable investigation (Phase 6).

Step 1  window from the alert's adaptive horizon (eq:investigation-window) or default.
Step 2  historical expansion via EE-derived tokens (eq:investigation-reference-set).
Step 4  checkpoint signature (eq:batch-checkpoint-verification), chain
        (eq:checkpoint-linkage), multiproof (eq:mmr-multiverify) -> verified set.
Step 5  payload key from the KA only for verified epochs; decrypt; drop decoys
        (eq:payload-recovery, eq:decoy-filter).
Step 6  identity resolution through the TD (eq:identity-resolution).
"""

from __future__ import annotations

from dataclasses import dataclass, field

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


class SecurityAnalyst:
    def __init__(self, bus: Bus, default_lookback: int):
        self.bus = bus
        self.alerts: list[Descriptor] = []
        self.default_lookback = default_lookback
        self.ee = self.cloud = self.ka = self.td = None  # wired by the system

    def receive_alert(self, d: Descriptor) -> None:
        self.alerts.append(d)

    def investigate(self, d: Descriptor) -> Investigation:
        e = d.epoch
        span = d.horizon if d.horizon is not None else self.default_lookback
        window = range(max(1, e - span + 1), e + 1)
        inv = Investigation(d, window)

        # Step 2: the EE resolves the current token internally and derives historical queries
        user = self.ee.resolve_current(e, d.token)
        queries = self.ee.investigation_queries(user, d.attack, window)
        refs = set(d.provenance)
        for tau, tok in queries.items():
            refs |= self.cloud.inv_query(tau, tok)

        # Step 3: evidence packages with per-epoch multiproofs
        ev = self.cloud.evidence(refs, window)
        cps = ev["checkpoints"]

        # Step 4: checkpoint signature + chain, then multiproof
        cp_ok = {}
        for tau, (cp, sig) in cps.items():
            ok = cp[0] == tau and verify(self.ka.pk_ka, H(encode(*cp)), sig)
            prev = cps.get(tau - 1)
            if ok and prev is not None:
                ok = cp[2] == prev[0][1]  # R_tau^prev == R_{tau-1}^MMR
            cp_ok[tau] = ok
        # completeness w.r.t. the requested references (rid-addressed; omission from the
        # search results themselves is not detectable by inclusion proofs)
        returned = {rid for pkg in ev["packages"].values() for rid in pkg["records"]}
        missing = refs - returned
        inv.missing_records = len(missing)
        incomplete = {rid[0] for rid in missing}
        inv.failed_epochs.extend(sorted(incomplete - set(ev["packages"])))
        verified = set()
        for tau, pkg in ev["packages"].items():
            cp, _ = pkg["checkpoint"]
            leaves = {rec.iota: leaf_hash(leaf_data(rec, ent)) for rec, ent in pkg["records"].values()}
            if tau not in incomplete and cp_ok.get(tau) and multiverify(leaves, pkg["proof"], cp[1], cp[3]):
                inv.verified_epochs.append(tau)
                verified |= set(pkg["records"])
            else:
                inv.failed_epochs.append(tau)
        inv.verified_records = len(verified)

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
