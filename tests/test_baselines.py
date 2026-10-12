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
