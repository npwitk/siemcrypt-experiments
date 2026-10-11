import random

import pytest

from siemcrypt.crypto import mmr, paillier
from siemcrypt.crypto.cms import CountMin
from siemcrypt.crypto.encoding import FixedPoint, encode
from siemcrypt.crypto.primitives import (
    AeadError,
    Signer,
    aead_decrypt,
    aead_encrypt,
    kdf,
    prf_token,
    verify,
)


# ---------------------------------------------------------------- encoding
def test_encoding_is_injective_on_tricky_inputs():
    pairs = [
        (("ab", "c"), ("a", "bc")),
        ((b"1",), ("1",)),
        ((1,), (-1,)),
        ((b"",), ()),
    ]
    for a, b in pairs:
        assert encode(*a) != encode(*b)


# ---------------------------------------------------------------- symmetric
def test_kdf_separates_labels_and_epochs():
    msk = b"\x01" * 32
    keys = {kdf(msk, x, e) for x in "PURCS" for e in (1, 2)}
    assert len(keys) == 10


def test_prf_tokens_equal_within_epoch_and_differ_across():
    msk = b"\x02" * 32
    k1, k2 = kdf(msk, "U", 1), kdf(msk, "U", 2)
    assert prf_token(k1, "alice") == prf_token(k1, "alice")
    assert prf_token(k1, "alice") != prf_token(k2, "alice")
    assert prf_token(k1, "alice") != prf_token(k1, "bob")


def test_aead_roundtrip_and_ad_binding():
    key = kdf(b"\x03" * 32, "P", 7)
    ad = encode(7, 3, "meta")
    iv, ct = aead_encrypt(key, b"payload", ad)
    assert aead_decrypt(key, iv, ct, ad) == b"payload"
    # transplanting into another epoch/bucket must fail (eq:aes-gcm)
    with pytest.raises(AeadError):
        aead_decrypt(key, iv, ct, encode(8, 3, "meta"))
    # any bit flip must fail
    bad = bytes([ct[0] ^ 1]) + ct[1:]
    with pytest.raises(AeadError):
        aead_decrypt(key, iv, bad, ad)


def test_signature():
    s = Signer()
    sig = s.sign(b"checkpoint")
    assert verify(s.pk, b"checkpoint", sig)
    assert not verify(s.pk, b"checkpoinT", sig)


# ---------------------------------------------------------------- Paillier
@pytest.fixture(scope="module")
def he():
    pk, sk = paillier.keygen(1024)  # small modulus keeps tests fast
    return pk, sk, paillier.Paillier(pk)


def test_paillier_homomorphism(he):
    pk, sk, P = he
    a, b = 123456, 987654
    ca, cb = P.encrypt(a), P.encrypt(b)
    assert paillier.decrypt(sk, pk, P.add(ca, cb)) == a + b
    assert paillier.decrypt(sk, pk, P.smul(ca, 5)) == 5 * a
    assert paillier.decrypt(sk, pk, P.sum([ca, cb, P.encrypt(1)])) == a + b + 1


def test_paillier_precomputation_used_and_semantic(he):
    pk, sk, P = he
    P.precompute(4)
    before = P.online_randomizers
    c1, c2 = P.encrypt(42), P.encrypt(42)
    assert c1 != c2  # randomized
    assert P.online_randomizers == before
    assert paillier.decrypt(sk, pk, c1) == 42


def test_fixed_point_and_negative_weights(he):
    pk, sk, P = he
    fp = FixedPoint(int(pk.n), frac_bits=16)
    vals = [1.5, -0.25, 3.0]
    total = P.sum(P.encrypt(fp.encode(v)) for v in vals)
    assert fp.decode(paillier.decrypt(sk, pk, total)) == pytest.approx(4.25)
    weighted = P.smul(P.encrypt(fp.encode(2.0)), fp.encode_weight(-3))
    assert fp.decode(paillier.decrypt(sk, pk, weighted)) == pytest.approx(-6.0)


def test_realness_indicator_cancels_decoys(he):
    """Decoys encrypt 0 features and X_{i,0} = 1 - delta_i (eq:realness-indicator)."""
    pk, sk, P = he
    real = [(5, 1), (7, 1)]
    decoy = [(0, 0)] * 3
    feats = P.sum(P.encrypt(x) for x, _ in real + decoy)
    count = P.sum(P.encrypt(r) for _, r in real + decoy)
    assert paillier.decrypt(sk, pk, feats) == 12
    assert paillier.decrypt(sk, pk, count) == 2


# ---------------------------------------------------------------- MMR
@pytest.mark.parametrize("n", [1, 2, 3, 7, 8, 13, 64, 100])
def test_mmr_multiproof_roundtrip(n):
    t = mmr.MMR()
    leaves = [mmr.leaf_hash(encode(i, "rec")) for i in range(n)]
    for lh in leaves:
        t.append_leaf_hash(lh)
    root = t.root()
    rng = random.Random(n)
    for k in {1, min(n, 3), n}:
        idx = rng.sample(range(n), k)
        proof = t.multiprove(idx)
        assert mmr.multiverify({i: leaves[i] for i in idx}, proof, root, n)


def test_mmr_rejects_any_tampering():
    n = 37
    t = mmr.MMR()
    leaves = [mmr.leaf_hash(encode(i)) for i in range(n)]
    for lh in leaves:
        t.append_leaf_hash(lh)
    root = t.root()
    idx = [2, 3, 17, 36]
    proof = t.multiprove(idx)
    good = {i: leaves[i] for i in idx}
    assert mmr.multiverify(good, proof, root, n)
    # modified leaf
    bad = dict(good)
    bad[17] = mmr.leaf_hash(encode("forged"))
    assert not mmr.multiverify(bad, proof, root, n)
    # substituted position (record moved)
    assert not mmr.multiverify({3: leaves[2], 2: leaves[3], 17: leaves[17], 36: leaves[36]}, proof, root, n)
    # modified proof node
    pos = next(iter(proof))
    tampered = dict(proof)
    tampered[pos] = b"\x00" * 32
    assert not mmr.multiverify(good, tampered, root, n)
    # wrong size (truncation / rollback)
    assert not mmr.multiverify(good, proof, root, n - 1)


def test_mmr_multiproof_shares_nodes():
    n = 1024
    t = mmr.MMR()
    for i in range(n):
        t.append(encode(i))
    idx = list(range(100, 164))  # 64 adjacent leaves
    multi = mmr.proof_size(t.multiprove(idx))
    individual = sum(mmr.proof_size(t.multiprove([i])) for i in idx)
    assert multi < individual / 10


def test_mmr_leaf_is_not_a_node():
    """Domain separation: an internal node value cannot verify as a leaf."""
    t = mmr.MMR()
    for i in range(4):
        t.append(encode(i))
    internal = t.node((1, 0))
    assert internal != mmr.leaf_hash(encode(0))


# ---------------------------------------------------------------- Count-Min
def test_countmin_never_underestimates_and_decays():
    cur = CountMin(512, 4)
    base = cur.like()
    truth = {}
    rng = random.Random(1)
    for _ in range(5000):
        k = f"user{rng.randint(0, 300)}".encode()
        cur.update(k)
        truth[k] = truth.get(k, 0) + 1
    assert all(cur.query(k) >= v for k, v in truth.items())
    base.decay_into(cur, rho=0.5)
    k0 = next(iter(truth))
    assert base.query(k0) == pytest.approx(0.5 * cur.query(k0))
