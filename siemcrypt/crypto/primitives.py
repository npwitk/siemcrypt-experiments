"""Symmetric primitives and signatures (eq:pp).

- ``H``: SHA-256 collision-resistant hash.
- ``prf_token``: epoch-scoped token F_K(H(v)) with HMAC-SHA256 as F (eq:tokens).
- ``kdf``: K_e^x = KDF(msk, x || e) with HKDF-SHA256 (eq:epoch-keys).
- ``aead_encrypt`` / ``aead_decrypt``: AES-256-GCM with associated data (eq:aes-gcm).
- ``Signer``: Ed25519 signatures for checkpoints (eq:checkpoint-signature).
"""

from __future__ import annotations

import hashlib
import hmac
import os

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .encoding import encode

KEY_LEN = 32
IV_LEN = 12


def H(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def prf(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def prf_token(key: bytes, value: str | bytes) -> bytes:
    """T = F_K(H(v)), eq:tokens."""
    v = value.encode() if isinstance(value, str) else value
    return prf(key, H(v))


def kdf(msk: bytes, label: str, epoch: int) -> bytes:
    """K_e^x = KDF(msk, x || e), eq:epoch-keys."""
    return HKDF(
        algorithm=hashes.SHA256(), length=KEY_LEN, salt=None, info=encode(label, epoch)
    ).derive(msk)


class AeadError(Exception):
    """Raised when AES-GCM authentication fails (record treated as tampered)."""


def aead_encrypt(key: bytes, plaintext: bytes, ad: bytes) -> tuple[bytes, bytes]:
    """Returns (IV, ciphertext||tag); a fresh random 96-bit IV per call."""
    iv = os.urandom(IV_LEN)
    return iv, AESGCM(key).encrypt(iv, plaintext, ad)


def aead_decrypt(key: bytes, iv: bytes, ciphertext: bytes, ad: bytes) -> bytes:
    try:
        return AESGCM(key).decrypt(iv, ciphertext, ad)
    except InvalidTag as exc:
        raise AeadError("AES-GCM authentication failed") from exc


class Signer:
    """Ed25519 signing key pair (the KA's (pk_KA, sk_KA))."""

    def __init__(self) -> None:
        self._sk = Ed25519PrivateKey.generate()
        self.pk: Ed25519PublicKey = self._sk.public_key()

    def sign(self, msg: bytes) -> bytes:
        return self._sk.sign(msg)


def verify(pk: Ed25519PublicKey, msg: bytes, sig: bytes) -> bool:
    try:
        pk.verify(sig, msg)
        return True
    except InvalidSignature:
        return False
