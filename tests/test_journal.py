"""Journal-version mechanisms: authenticated EPII, ACL, graph and state lineage, LAPH."""

import os
import random
from collections import Counter, defaultdict

import pytest

from siemcrypt import lineage
from siemcrypt.crypto import mdict
from siemcrypt.data.synth import SynthConfig, default_profiles_and_contexts, generate
from siemcrypt.laph import plan_decoys, tier
from siemcrypt.model import Config
from siemcrypt.system import SIEMCrypt

CFG = Config(paillier_bits=512, agg_features=("count", "bytes"), seed=1, acl=True, precompute_workers=0)


def _run(cfg=CFG, seed=3):
    events, _ = generate(SynthConfig(epochs=4, events_per_epoch=400, n_users=60, seed=seed))
    profiles, contexts = default_profiles_and_contexts()
    s = SIEMCrypt(cfg, profiles, contexts)
    s.run(events)
    return s


@pytest.fixture(scope="module")
def acl_run():
    return _run()


# ============================================================================ Merkle dictionary
@pytest.mark.parametrize("n", [0, 1, 2, 3, 7, 64, 100])
def test_mdict_membership_and_non_membership(n):
    rng = random.Random(n)
    items = {os.urandom(8): os.urandom(32) for _ in range(n)}
    t = mdict.MerkleDict(items)
    keys = list(items)
    absent = [os.urandom(8) for _ in range(5)] + [b"", b"\xff" * 9]
    query = rng.sample(keys, min(len(keys), 5)) + absent
    got = mdict.verify(t.root(), query, t.prove(query))
    assert got is not None
    for k in query:
        assert got[k] == items.get(k)


def test_mdict_rejects_tampered_proof():
    items = {bytes([i]) * 4: os.urandom(32) for i in range(1, 40, 2)}
    t = mdict.MerkleDict(items)
    present, absent = b"\x05" * 4, b"\x06" * 4
    pf = t.prove([present, absent])
    # claim a present key is absent by dropping its leaf
    i = t.keys.index(present)
    bad = mdict.DictProof(pf.n, {j: v for j, v in pf.entries.items() if j != i}, dict(pf.nodes))
    assert mdict.verify(t.root(), [present], bad) is None
    # change a value
    bad = mdict.DictProof(pf.n, {**pf.entries, i: (present, os.urandom(32))}, dict(pf.nodes))
    assert mdict.verify(t.root(), [present], bad) is None
    # wrong leaf count
    assert mdict.verify(t.root(), [present], mdict.DictProof(pf.n - 1, pf.entries, pf.nodes)) is None


# ============================================================================ authenticated EPII
def test_posting_verification_detects_omission_and_substitution(acl_run):
    s = acl_run
    e = 2
    tokens = {"C": frozenset({s.ee.token("C", "auth_fail", e, s.ka.epoch_keys(e))})}
    Q, postings, proof = s.cloud.auth_candidates(e, tokens)
    root = s.cloud.checkpoints[e][0][2]
    assert Q and lineage.verify_postings(root, tokens, postings, proof)
    (k, lst), = postings.items()
    assert not lineage.verify_postings(root, tokens, {k: lst[1:]}, proof)
    other = next(i for i in range(len(s.cloud.by_epoch[e])) if i not in lst)
    assert not lineage.verify_postings(root, tokens, {k: sorted(lst[1:] + [other])}, proof)
    # stale index state: the posting proof of another epoch
    assert not lineage.verify_postings(s.cloud.checkpoints[e - 1][0][2], tokens, postings, proof)


# ============================================================================ ACL
def test_honest_run_accepts_every_transition(acl_run):
    s = acl_run
    assert s.ee.acl_log and all(r["ok"] for r in s.ee.acl_log)
    assert s.ee.stats["acl_reject"] == s.ee.stats["graph_reject"] == s.ee.stats["graph_omitted"] == 0
    assert all(d.state_commitment for d in s.sa.alerts if d.attack)


def test_acl_scores_equal_unauthenticated_run(acl_run):
    plain = _run(Config(**{**CFG.__dict__, "acl": False}))
    key = lambda log: sorted((e, u, a, round(S, 9)) for (e, u, a, S, *_) in log)  # noqa: E731
    assert key(plain.ee.score_log) == key(acl_run.ee.score_log)


def test_modified_aggregate_is_rejected_before_release():
    s = _run()
    orig = s.cloud.acl_request

    def tampered(q, fi):
        req = orig(q, fi)
        f = q["feats"][0]
        req["aggs"] = {**req["aggs"], f: s.cloud.he.add(req["aggs"][f], s.cloud.he.encrypt(1))}
        return req

    s.cloud.acl_request = tampered
    n0 = len(s.ka.audit)
    s.run_epoch(99, [])  # empty epoch: every context still goes through ACL
    assert s.ee.stats["acl_reject"] == len(s.ee.contexts)
    assert len(s.ka.audit) == n0  # nothing released


def test_modified_graph_update_is_not_admitted():
    s = _run()
    orig = s.cloud.contract

    def tampered(epoch, Z):
        ups, mu = orig(epoch, Z)
        if ups:
            tu, a, z, refs, cg = ups[0]
            ups[0] = (tu, a, [z[0] + 5] + list(z[1:]), refs, cg)
        return ups, mu

    s.cloud.contract = tampered
    events, _ = generate(SynthConfig(epochs=2, events_per_epoch=300, n_users=60, seed=9))
    s.run_epoch(50, [e for e in events if e.ts < 3600])
    assert s.ee.stats["graph_reject"] >= 1


def test_omitted_search_result_detected_in_investigation(acl_run):
    s = acl_run
    d = next(d for d in s.sa.alerts if d.attack)
    orig = s.cloud.inv_query_auth

    def omit(epoch, tokens):
        Q, postings, proof = orig(epoch, tokens)
        extra = sorted(Q - d.provenance)
        return (Q - set(extra[:1])) if extra else Q, postings, proof

    s.cloud.inv_query_auth = omit
    from dataclasses import replace
    inv = s.investigate(replace(d, attack=None))
    s.cloud.inv_query_auth = orig
    assert inv.index_failed_epochs


# ============================================================================ LAPH
def test_laph_deficits_fill_tiers_with_real_relations():
    events, _ = generate(SynthConfig(epochs=2, events_per_epoch=150, n_users=40, seed=5))
    rng = random.Random(0)
    gamma_of = {("U", ev.user): 2.0 for ev in events} | {("R", ev.res): 1.0 for ev in events}
    decoys = plan_decoys(events, gamma_of, rng)
    rel = {(ev.user, ev.res) for ev in events}
    cs = {(ev.user, ev.res, ev.cat, ev.src) for ev in events}
    assert all((u, r) in rel and (u, r, c, s) in cs for u, r, c, s, *_ in decoys)
    cnt = Counter(ev.user for ev in events)
    pad = Counter(u for u, *_ in decoys)
    for u, c in cnt.items():
        assert c + pad[u] == tier(c, 2.0)


def test_laph_run_pads_only_exposed_values_and_drops_decoys():
    s = _run(Config(paillier_bits=512, agg_features=("count", "bytes"), seed=1, padding="laph", precompute_workers=0))
    assert s.ee.stats["decoy"] > 0
    assert not any(s.ee.dummy.values())  # no dummy tokens: decoys reuse real values
    real_tokens = {t for (e, d, v), t in s.ee._tok_cache.items() if d == "U"}
    per = defaultdict(set)
    for rid, ent in s.cloud.entries.items():
        per[rid in s.ee.decoy_rids].add(ent.tokens[0])
    assert per[True] <= real_tokens
    d = next(d for d in s.sa.alerts if d.attack)
    inv = s.investigate(d)
    assert not inv.failed_epochs and inv.identity is not None



def test_padded_entities_land_exactly_on_tiers():
    """Entity tiers are exact even when resources are padded too; only unpadded entities
    absorb the resource pass."""
    events, _ = generate(SynthConfig(epochs=2, events_per_epoch=300, n_users=40, seed=6))
    cnt = Counter(ev.user for ev in events)
    heavy = {u for u, _ in cnt.most_common(10)}
    gamma_of = {("U", u): (4.0 if u in heavy else 1.0) for u in cnt} | {("R", ev.res): 2.0 for ev in events}
    pad = Counter(d[0] for d in plan_decoys(events, gamma_of, random.Random(1)))
    for u in heavy:
        assert cnt[u] + pad[u] == tier(cnt[u], 4.0)


def test_epoch_scoped_laph_runs_end_to_end():
    cfg = Config(paillier_bits=512, agg_features=("count", "bytes"), seed=1, padding="laph", laph_scope="epoch",
                 laph_gamma=(2.0, 4.0), precompute_workers=0)
    s = _run(cfg)
    assert s.ee.stats["decoy"] > 0 and not any(s.ee.dummy.values())
    d = next(d for d in s.sa.alerts if d.attack)
    inv = s.investigate(d)
    assert not inv.failed_epochs and inv.identity is not None and inv.decoys_dropped > 0
