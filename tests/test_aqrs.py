"""Journal v2 AQRS: cohort execution, real-only ACL, stable and sticky cohorts."""

import random
import sys
from collections import Counter
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "experiments"))

from common import config  # noqa: E402

from siemcrypt.aqrs import AQRS, Spec, vtier  # noqa: E402
from siemcrypt.data.synth import SynthConfig, default_profiles_and_contexts, generate  # noqa: E402
from siemcrypt.system import SIEMCrypt  # noqa: E402


def _tuples(n_users=40):
    rng = random.Random(3)
    t = Counter()
    for i in range(n_users):
        for _ in range(rng.randint(1, 30)):
            t[(f"u{i}", "r1", "auth_fail", "auth")] += 1
    return t


def test_cover_compatibility_and_stability():
    cfg = config("J", aqrs="fixed", aqrs_fixed_k=3)
    a = AQRS(cfg, random.Random(1))
    a.start_epoch(_tuples())
    s = Spec("U", "u0", None)
    m1, info = a.issue(s)
    m2, _ = a.issue(s)
    assert m1 == m2 and m1[0] == s  # stable within the epoch, real first
    vol = a.volumes(s.sigma)
    assert all(vtier(vol[m.value]) == vtier(vol["u0"]) for m in m1)
    assert info["k_eff"] == len(m1) <= 3


def test_dynamic_cover_redraws():
    cfg = config("J", aqrs="fixed", aqrs_fixed_k=3, aqrs_select="random", aqrs_dynamic=True)
    a = AQRS(cfg, random.Random(1))
    t = Counter({(f"u{i}", "r", "c", "s"): 5 for i in range(30)})  # one tier, 29 covers
    a.start_epoch(t)
    draws = {tuple(m.value for m in a.issue(Spec("U", "u0", None))[0]) for _ in range(10)}
    assert len(draws) > 1


def test_sticky_profile_does_not_escalate():
    t = Counter({(f"u{i}", "r", "c", "s"): 5 for i in range(30)})
    for sticky, expect_change in ((False, True), (True, False)):
        cfg = config("J", aqrs="adaptive", aqrs_sticky=sticky)
        a = AQRS(cfg, random.Random(1))
        a.start_epoch(t)
        ks = [a.issue(Spec("U", "u0", None))[1]["k_eff"] for _ in range(4)]
        assert (len(set(ks)) > 1) == expect_change


def _system(**kw):
    cfg = config("J", **kw)
    ev, _ = generate(SynthConfig(epochs=2, events_per_epoch=300, n_users=40, n_low_and_slow=0, n_exfil=0))
    p, c = default_profiles_and_contexts()
    s = SIEMCrypt(cfg, p, c)
    rng = random.Random(2)

    def hunter(e):
        us = sorted({t[0] for t in s.ee.epoch_tuples})
        return [Spec("U", rng.choice(us), None) for _ in range(4)]
    s.hunter = hunter
    s.run(ev)
    return s


def test_cohort_processed_alike_and_only_real_verified():
    s = _system(aqrs="fixed", aqrs_fixed_k=3)
    n_members = sum(h["k_eff"] for h in s.ee.hunt_log)
    assert s.bus.count[("cloud", "ee", "cohort_req")] == n_members
    assert all(h["ok"] for h in s.ee.hunt_log)
    hunt_checks = [r for r in s.ee.acl_log if r["kind"] == "phase3" and r["qid"] in {h["real"] for h in s.ee.hunt_log}]
    assert len(hunt_checks) == len(s.ee.hunt_log)  # covers never reach ACL
    assert s.ee.stats["acl_reject"] == 0 and s.ee.stats["graph_reject"] == 0 and s.ee.stats["graph_omitted"] == 0


def test_ee_side_graph_keeps_hunt_evidence_from_cloud():
    s = _system(aqrs="fixed", aqrs_fixed_k=3, aqrs_graph="ee")
    assert not any(k == "evidence_z" and o.get("attack") == "hunt" for _, k, o in s.bus.cloud_view)
    assert s.ee.stats["graph_reject"] == 0 and s.ee.stats["graph_omitted"] == 0
