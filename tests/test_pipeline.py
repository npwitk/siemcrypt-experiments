"""End-to-end tests of Phases 1-6 on synthetic data (512-bit Paillier for speed)."""

from collections import Counter, defaultdict
from dataclasses import replace

import pytest

from siemcrypt.data.synth import SynthConfig, default_profiles_and_contexts, generate
from siemcrypt.model import Config, Context, Policy
from siemcrypt.parties.ee import tier
from siemcrypt.protocol import ProtectedRecord
from siemcrypt.system import SIEMCrypt

CFG = Config(paillier_bits=512, agg_features=("count", "bytes"), gamma=2.0, seed=1)  # decoys on: tests cover padding


@pytest.fixture(scope="module")
def run():
    events, truth = generate(SynthConfig(epochs=6, events_per_epoch=600, n_users=80))
    profiles, contexts = default_profiles_and_contexts()
    s = SIEMCrypt(CFG, profiles, contexts)
    reports = s.run(events)
    return s, events, truth, reports


def test_tier_ladder():
    assert [tier(c, 2.0) for c in (1, 2, 3, 5, 9)] == [1, 2, 4, 8, 16]
    assert tier(1, 1.5) == 1


def test_padding_quantizes_entity_and_resource_volumes(run):
    """Per-bucket volume of every U and R token is a tier value (Phase 1, Step 5)."""
    s, *_ = run
    vol = defaultdict(Counter)
    for entry in s.cloud.entries.values():
        for d, T in (("U", entry.tokens[0]), ("R", entry.tokens[1])):
            vol[(entry.epoch, entry.bucket, d)][T] += 1
    for counts in vol.values():
        for c in counts.values():
            assert c == tier(c, CFG.gamma)


def test_released_aggregates_equal_plaintext(run):
    """Exactness: SG-HEF releases equal the plaintext count over real events (decoys add 0)."""
    s, events, _, reports = run
    for r in reports:
        real = sum(1 for ev in events if s.epoch_of(ev.ts) == r.epoch and ev.cat == "auth_fail")
        rel = next(x for x in r.releases if x["qid"] == "q_auth_fail")
        assert rel["y"]["count"] == real


def test_cloud_view_contains_no_plaintext_identities(run):
    s, events, *_ = run
    users = {ev.user.encode() for ev in events}
    blob = repr(s.bus.cloud_view).encode()
    assert not any(u in blob for u in users)


def test_brute_force_detected_and_investigated(run):
    s, _, truth, _ = run
    alerted = {(d.attack, s.ee.resolve_current(d.epoch, d.token)) for d in s.sa.alerts if d.attack}
    for gt in truth:
        if gt.kind == "brute_force":
            assert ("cred_access", gt.user) in alerted
    d = next(d for d in s.sa.alerts if d.attack and s.ee.resolve_current(d.epoch, d.token) ==
             next(g.user for g in truth if g.kind == "brute_force"))
    inv = s.investigate(d)
    assert inv.failed_epochs == []
    assert inv.verified_records > 0 and inv.plaintexts
    assert inv.identity == s.ee.resolve_current(d.epoch, d.token)


def test_tampering_detected():
    events, _ = generate(SynthConfig(epochs=3, events_per_epoch=300, n_users=40, n_low_and_slow=0, n_exfil=0))
    profiles, contexts = default_profiles_and_contexts()
    s = SIEMCrypt(CFG, profiles, contexts)
    s.run(events)
    d = next(d for d in s.sa.alerts if d.attack)
    rid = next(iter(d.provenance))
    rec = s.cloud.records[rid]
    s.cloud.records[rid] = ProtectedRecord(rec.epoch, rec.iota, rec.iv,
                                           bytes([rec.ct[0] ^ 1]) + rec.ct[1:], rec.X, rec.X0)
    inv = s.investigate(d)
    assert rid[0] in inv.failed_epochs


def test_k_min_downgrades_value_to_decision():
    events, _ = generate(SynthConfig(epochs=1, events_per_epoch=200, n_users=40,
                                     n_brute_force=0, n_low_and_slow=0, n_exfil=0))
    rare_user = Counter(ev.user for ev in events).most_common()[-1][0]
    ctx = [Context("q_one", "cred_access", users=frozenset({rare_user}), feats=("count",),
                   policy=Policy.VALUE, threshold=1)]
    profiles, _ = default_profiles_and_contexts()
    s = SIEMCrypt(replace(CFG, k_min=50), profiles, ctx)
    s.run(events)
    rec = s.ka.audit[0]
    assert rec.policy is Policy.VALUE and rec.effective is Policy.DECISION
    assert s.reports[0].releases[0]["y"]["count"] in (0, 1)


def test_persistent_tokens_ablation_reuses_entity_tokens():
    events, _ = generate(SynthConfig(epochs=2, events_per_epoch=200, n_users=20, n_brute_force=0,
                                     n_low_and_slow=0, n_exfil=0))
    profiles, contexts = default_profiles_and_contexts()
    for persistent in (False, True):
        s = SIEMCrypt(replace(CFG, gamma=1.0, persistent_tokens=persistent), profiles, contexts)
        s.run(events)
        shared = set(s.ee.user_of[1]) & set(s.ee.user_of[2])
        assert bool(shared) is persistent


def test_omitted_requested_record_fails_epoch(run):
    s, *_ = run
    d = next(d for d in s.sa.alerts if d.attack)
    rid = next(iter(d.provenance))
    orig = s.cloud.evidence
    s.cloud.evidence = lambda refs, window: orig(refs - {rid}, window)
    try:
        inv = s.investigate(d)
    finally:
        s.cloud.evidence = orig
    assert inv.missing_records == 1 and rid[0] in inv.failed_epochs


def test_precomputed_randomizers_cover_ingestion():
    events, _ = generate(SynthConfig(epochs=2, events_per_epoch=100, n_users=20))
    profiles, contexts = default_profiles_and_contexts()
    s = SIEMCrypt(replace(CFG, precompute_workers=1), profiles, contexts)
    s.run(events)
    assert s.ee.he.online_randomizers == 0 and s.ee.stats["t_offline"] > 0


def test_sigmoid_is_stable_for_extreme_scores():
    from siemcrypt.parties.ee import _sigmoid

    assert _sigmoid(-1e6) == 0.0 and _sigmoid(1e6) == 1.0 and abs(_sigmoid(0) - 0.5) < 1e-12
