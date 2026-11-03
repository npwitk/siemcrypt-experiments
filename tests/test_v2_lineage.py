"""Journal v2: versioned profiles (pid_a), Fixed-Window and No-Graph ablations, C_Inv."""

import sys
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "experiments"))

from common import config  # noqa: E402

from siemcrypt import lineage  # noqa: E402
from siemcrypt.data.synth import SynthConfig, default_profiles_and_contexts, generate  # noqa: E402
from siemcrypt.system import SIEMCrypt  # noqa: E402

SC = SynthConfig(epochs=4, events_per_epoch=300, n_users=40, seed=5, n_low_and_slow=2, lns_epochs=3)


def _run(cfg, change_at=None):
    events, _ = generate(SC)
    profiles, contexts = default_profiles_and_contexts()
    s = SIEMCrypt(cfg, profiles, contexts)
    by = {}
    for ev in events:
        by.setdefault(s.epoch_of(ev.ts), []).append(ev)
    for e in sorted(by):
        if e == change_at:
            p = s.ee.profiles["cred_access"]
            s.ee.update_profile(replace(p, version=2))
        s.run_epoch(e, by[e])
    return s


def test_pid_depends_on_version_and_parameters():
    p = default_profiles_and_contexts()[0][0]
    assert lineage.pid(p) != lineage.pid(replace(p, version=2))
    assert lineage.pid(p) != lineage.pid(replace(p, Theta=p.Theta + 1))
    assert lineage.genesis(lineage.pid(p)) != lineage.genesis(lineage.pid(replace(p, version=2)))


def test_profile_change_starts_new_lineages():
    s = _run(config("J", paillier_bits=256), change_at=3)
    cur = lineage.pid(s.ee.profiles["cred_access"])
    assert all(k[2] == cur for k in s.ee.state if k[1] == "cred_access")
    assert s.ee.stats["lineage_retired"] > 0
    assert all(a["born"] == a["version"] for a in s.ee.alert_log if a["epoch"] >= 3)


def test_no_profile_bind_keeps_state_across_versions():
    s = _run(config("J", paillier_bits=256, profile_bind=False), change_at=3)
    assert all(len(k) == 2 for k in s.ee.state)
    assert s.ee.stats["lineage_retired"] == 0


def test_fixed_window_and_no_graph_run():
    s = _run(config("S", paillier_bits=256, hist_window=2))
    assert all(r[3] == 2 for r in s.ee.horizon_log)
    s = _run(config("S", paillier_bits=256, no_graph=True))
    assert all(all(v == 0.0 for v in z[:5]) for _, _, _, _, z, _ in s.ee.score_log)


def test_c_inv_binds_window_and_references():
    s = _run(config("J", paillier_bits=256))
    d = next(d for d in s.sa.alerts if d.attack)
    inv = s.investigate(d)
    assert inv.c_inv is not None
    assert s.investigate(d).c_inv == inv.c_inv            # deterministic
    if d.epoch > 1:
        assert s.investigate(d, span=1).c_inv != inv.c_inv or len(inv.window) == 1
