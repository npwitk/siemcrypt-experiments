"""Wire objects shared by all parties and their canonical encodings.

ProtectedRecord  L~_i = (rid_i, C_i^P, X_i, meta_i)          eq:protected-record
IndexEntry       I_i  = (T_i, b(t_i), rid_i)                eq:index-entry
leaf_data        <rid_i, H(L~_i), H(I_i)>                   eq:mmr-leaf (the MMR adds 0x00)
"""

from __future__ import annotations

from dataclasses import dataclass

from .crypto.encoding import encode
from .crypto.primitives import H

DIMS = ("U", "R", "C", "S")
META = "v1"  # processing metadata permitted to remain visible; identical for decoys


@dataclass(frozen=True)
class ProtectedRecord:
    epoch: int
    iota: int          # leaf index in the epoch MMR; rid = (epoch, iota)
    iv: bytes
    ct: bytes          # AES-GCM over (delta || payload)
    X: tuple           # HE features in J_AGG order
    X0: object         # realness indicator HE.Enc(1 - delta)
    meta: str = META

    @property
    def rid(self) -> tuple[int, int]:
        return (self.epoch, self.iota)


@dataclass(frozen=True)
class IndexEntry:
    tokens: tuple[bytes, bytes, bytes, bytes]  # (T_U, T_R, T_C, T_S)
    bucket: int
    epoch: int
    iota: int

    @property
    def rid(self) -> tuple[int, int]:
        return (self.epoch, self.iota)


def ser_record(r: ProtectedRecord) -> bytes:
    return encode(r.epoch, r.iota, r.iv, r.ct, *[int(x) for x in r.X], int(r.X0), r.meta)


def ser_entry(i: IndexEntry) -> bytes:
    return encode(*i.tokens, i.bucket, i.epoch, i.iota)


def leaf_data(r: ProtectedRecord, i: IndexEntry) -> bytes:
    return encode(r.epoch, r.iota, H(ser_record(r)), H(ser_entry(i)))


def aead_ad(epoch: int, bucket: int, meta: str = META) -> bytes:
    """AD_i = (e, b(t_i), meta_i), eq:aes-gcm."""
    return encode(epoch, bucket, meta)
