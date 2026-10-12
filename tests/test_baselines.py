"""Published baselines (B5, B7, B8): correctness of search and verification."""

import random

from siemcrypt.baselines import prisiem
from siemcrypt.baselines.evseb import EVSEB
from siemcrypt.baselines.mktree import MKTree
from siemcrypt.data.synth import SynthConfig, generate
from siemcrypt.model import Event


def _stream():
    events, _ = generate(SynthConfig(epochs=2, events_per_epoch=300, n_users=20))
    by = {}
    for ev in events:
        by.setdefault(int(ev.ts // 3600) + 1, []).append(ev)
    return events, by


def test_evseb_boolean_search_and_verification():
    events, by = _stream()
    s = EVSEB()
    for e in sorted(by):
        s.ingest_epoch(e, by[e])
    u, c = events[0].user, events[0].cat
    lids = sorted(s.store)
    truth_u = {lid for lid, ev in zip(lids, sorted(events, key=lambda x: x.ts)) if ev.user == u}
    assert s.search([f"u:{u}"]) == truth_u
    both = s.search([f"u:{u}", f"c:{c}"], "AND")
    assert both <= truth_u and both
    tok = s.register("analyst", frozenset({c}))
    assert s.search([f"u:{u}"], token=tok, ltype=c) and not s.search([f"u:{u}"], token=tok, ltype="other")
    ok, bad = s.verify(truth_u)
    assert ok == truth_u and not bad
    lid = next(iter(truth_u))
    e, iv, ct, miv, mct = s.store[lid]
    s.store[lid] = (e, iv, bytes([ct[0] ^ 1]) + ct[1:], miv, mct)
    assert s.verify(truth_u)[1] == {lid}  # TraceTamperedNode pinpoints the record


def test_mktree_batch_verification_and_tamper():
    _, by = _stream()
    m = MKTree(stride=2)
    for e in sorted(by):
        m.ingest_epoch(e, by[e])
    refs = set(random.Random(0).sample(sorted(m.store), 40))
    assert m.verify(refs) == (refs, set())
    r = next(iter(refs))
    iv, ct, ad, d, sg = m.store[r]
    m.store[r] = (iv, bytes([ct[0] ^ 1]) + ct[1:], ad, d, sg)
    assert r in m.verify(refs)[1]


def test_mktree_batch_cost_bound():
    """Theorem IV-G.1: at most n(L - s) + g s internal hashes (plus leaf and signature hashes)."""
    evs = [Event("s", "u", "r", "t", {}, bytes([i % 256]) * 50, float(i)) for i in range(256)]
    m = MKTree(stride=3)
    m.ingest_epoch(1, evs)
    sel = {(1, "t", i) for i in range(0, 256, 16)}
    h0 = m.hashes
    m.verify(sel)
    n, L, s, g = len(sel), 8, 3, len({i >> (8 - 3) for _, _, i in sel})
    assert m.hashes - h0 <= n * (L - s) + g * s + 2 * n + 1


def test_prisiem_gate_model():
    assert prisiem.gates_per_event(1) == 256 + 295
    c = prisiem.cost(events=10, entities=2, epochs=1, contexts=1, t_gate_us=1000.0)
    assert c["gates"] == 10 * 551 + 2 * 48 and abs(c["seconds"] - c["gates"] / 1000) < 1e-9


def test_zhang_audit_accepts_clean_and_rejects_sampled_tamper():
    import os

    from siemcrypt.baselines import zhang

    z = zhang.ZhangAudit(s=4)
    z.upload(1, [os.urandom(512) for _ in range(6)])
    assert z.audit(1, 6, b"t0")
    z.blocks[1] = [bytes([b[0] ^ 1]) + b[1:] for b in z.blocks[1]]  # every block changed: any sample hits
    assert not z.audit(1, 3, b"t1")
    assert abs(zhang.detection_probability(48, 1, 16) - (1 - (47 / 48) ** 16)) < 1e-12


def test_wingarz_ckks_matches_plaintext_network():
    import numpy as np
    import pytest

    pytest.importorskip("tenseal")
    from siemcrypt.baselines import wingarz as W

    rng = np.random.default_rng(0)
    layers = [(rng.normal(size=(9, 50)), rng.normal(size=9)), (rng.normal(size=(4, 9)) * 0.1, rng.normal(size=4)),
              (rng.normal(size=(2, 4)) * 0.01, rng.normal(size=2))]
    X = rng.random((64, 50)) * 0.1
    p, st = W.ckks_infer(W.ckks_context(), layers, X)
    assert (p == W.plain_predict(layers, X)).mean() >= 0.98 and st["vectors"] == 64


def test_ogawa_anonymization_bins_and_k_anonymity():
    import numpy as np

    from siemcrypt.baselines import ogawa as O

    d = O._bins([0, 0.005, 0.05, 0.5, 5, 50, 500], O.DUR_EDGES, True).argmax(1)
    assert list(d) == [0, 1, 2, 3, 4, 5, 6]
    s = O._bins([0, 1, 5, 50, 500, 5000], O.SRC_EDGES, False).argmax(1)
    assert list(s) == [0, 0, 1, 2, 3, 4]
    assert list(O.k_anonymity(np.array([[1, 2], [1, 2], [3, 4]]))) == [2, 2, 1]
