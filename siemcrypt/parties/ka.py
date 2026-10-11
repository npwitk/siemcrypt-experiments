"""Key Authority (KA): epoch keys, HE decryption under release policy, checkpoint signing.

- Epoch keys K_e^x = KDF(msk, x || e) (eq:epoch-keys).
- Release with effective policy and minimum support k_min (eq:effective-policy,
  eq:release-policy); at most one release per (context, epoch, feature), audited.
- Checkpoint signatures (eq:checkpoint-signature).
- Payload keys released to the SA only for verified evidence (Phase 6, Step 5).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..crypto import paillier
from ..crypto.encoding import FixedPoint, encode
from ..crypto.primitives import H, Signer, kdf
from ..model import Config, Policy

DIMS = ("P", "U", "R", "C", "S")


@dataclass
class ReleaseRecord:
    qid: str
    epoch: int
    feature: str
    policy: Policy
    effective: Policy
    support: int


class KeyAuthority:
    def __init__(self, cfg: Config, msk: bytes | None = None):
        import os

        self.cfg = cfg
        self._msk = msk or os.urandom(32)
        self.pk_h, self._sk_h = paillier.keygen(cfg.paillier_bits)
        self.signer = Signer()
        self.pk_ka = self.signer.pk
        self.fp = FixedPoint(int(self.pk_h.n), cfg.frac_bits)
        self.audit: list[ReleaseRecord] = []
        self._released: set[tuple[str, int, str]] = set()
        self.decryptions = 0

    # ---------------------------------------------------------------- keys
    def epoch_keys(self, epoch: int) -> dict[str, bytes]:
        """K_e for the EE (current epoch, or past epochs for authorized expansion).

        Ablation A4 (persistent_tokens) fixes the token keys to epoch 0; the payload key
        still rotates."""
        tok_epoch = 0 if self.cfg.persistent_tokens else epoch
        return {x: kdf(self._msk, x, epoch if x == "P" else tok_epoch) for x in DIMS}

    def payload_key(self, epoch: int, verified: bool) -> bytes:
        """K_tau^P, released only after the SA reports successful verification."""
        if not verified:
            raise PermissionError("payload key released only for verified evidence")
        return kdf(self._msk, "P", epoch)

    # ---------------------------------------------------------------- release
    def _dec(self, c) -> int:
        self.decryptions += 1
        return paillier.decrypt(self._sk_h, self.pk_h, c)

    def release(self, qid: str, epoch: int, policy: Policy, threshold: float,
                aggregates: dict[str, object], realness) -> dict[str, float | int | None]:
        """Release_{Pi_q}(A) for each feature aggregate of one context."""
        support = self.fp.decode_int(self._dec(realness))  # n_q, never released
        effective = policy
        if policy is Policy.VALUE and support < self.cfg.k_min:
            effective = Policy.DECISION
        out: dict[str, float | int | None] = {}
        for feat, ct in aggregates.items():
            key = (qid, epoch, feat)
            if key in self._released:
                raise PermissionError(f"context {qid} already released {feat} for epoch {epoch}")
            self._released.add(key)
            self.audit.append(ReleaseRecord(qid, epoch, feat, policy, effective, support))
            if effective is Policy.HIDE:
                out[feat] = None
                continue
            value = self.fp.decode(self._dec(ct)) if self.cfg.frac_bits else self.fp.decode_int(self._dec(ct))
            out[feat] = value if effective is Policy.VALUE else int(value >= threshold)
        return out

    # ---------------------------------------------------------------- checkpoints
    def sign_checkpoint(self, cp: tuple) -> bytes:
        return self.signer.sign(H(encode(*cp)))


GENESIS = H(b"genesis")
