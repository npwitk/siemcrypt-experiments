"""Synthetic multi-source log generator with injected attacks and ground truth.

Used for development and for the controlled experiments (low-and-slow curves, leakage
attacks with known auxiliary distributions). For the paper, background traffic should
come from a real dataset (AIT-LDSv2, LANL) with these attacks injected on top.

Attack types
  brute_force   one burst of failed logins in a single epoch           (cred_access)
  low_and_slow  a few failed logins per epoch over many epochs          (cred_access)
  exfil         repeated large outbound transfers over several epochs   (exfil)
  coordinated   a few weak events of one entity on 3 sources in one epoch (multi_source)
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

from ..model import AttackProfile, Context, Event, Policy

SOURCES = ("auth", "fw", "ids", "web")
BENIGN_CATS = {
    "auth": [("auth_success", 0.93), ("auth_fail", 0.07)],
    "fw": [("conn_allowed", 0.9), ("conn_denied", 0.1)],
    "ids": [("ids_info", 0.95), ("ids_alert", 0.05)],
    "web": [("web_request", 0.85), ("data_transfer", 0.15)],
}
SOURCE_MIX = [("auth", 0.35), ("fw", 0.3), ("ids", 0.1), ("web", 0.25)]


@dataclass
class SynthConfig:
    n_users: int = 200
    n_hosts: int = 40
    n_external: int = 20
    epochs: int = 8
    epoch_len: float = 3600.0
    events_per_epoch: int = 1500
    zipf_s: float = 1.1
    seed: int = 7
    n_brute_force: int = 2
    n_low_and_slow: int = 2
    n_exfil: int = 1
    lns_per_epoch: int = 4
    lns_epochs: int = 5
    n_coordinated: int = 0
    coord_per_source: int = 3


@dataclass
class GroundTruth:
    attack_id: str
    kind: str
    attack_class: str
    user: str
    epochs: list[int] = field(default_factory=list)


def _pick(rng: random.Random, weighted):
    r, acc = rng.random(), 0.0
    for item, w in weighted:
        acc += w
        if r <= acc:
            return item
    return weighted[-1][0]


def _payload(rng: random.Random, src: str, cat: str, user: str, res: str) -> bytes:
    return f"{src} {cat} user={user} target={res} pid={rng.randint(100, 99999)}".encode()


def _event(rng, ts, src, cat, user, res, label=None, nbytes=None) -> Event:
    feats = {"count": 1}
    if cat == "data_transfer":
        feats["bytes"] = nbytes if nbytes is not None else rng.randint(1, 50)  # KB
    return Event(src, user, res, cat, feats, _payload(rng, src, cat, user, res), ts, label)


def generate(cfg: SynthConfig) -> tuple[list[Event], list[GroundTruth]]:
    rng = random.Random(cfg.seed)
    users = [f"user{i:03d}" for i in range(cfg.n_users)]
    hosts = [f"host{i:02d}" for i in range(cfg.n_hosts)]
    external = [f"ext{i:02d}.example.net" for i in range(cfg.n_external)]
    weights = [1 / (i + 1) ** cfg.zipf_s for i in range(cfg.n_users)]
    events: list[Event] = []

    # benign background
    for e in range(cfg.epochs):
        t0 = e * cfg.epoch_len
        for _ in range(cfg.events_per_epoch):
            src = _pick(rng, SOURCE_MIX)
            cat = _pick(rng, BENIGN_CATS[src])
            user = rng.choices(users, weights)[0]
            res = rng.choice(external if cat == "data_transfer" else hosts)
            events.append(_event(rng, t0 + rng.random() * cfg.epoch_len, src, cat, user, res))

    truth: list[GroundTruth] = []
    n_att = cfg.n_brute_force + cfg.n_low_and_slow + cfg.n_exfil + cfg.n_coordinated
    attackers = rng.sample(users[cfg.n_users // 2:], n_att)
    it = iter(attackers)

    for k in range(cfg.n_brute_force):
        u, e = next(it), rng.randrange(1, cfg.epochs)
        gt = GroundTruth(f"bf{k}", "brute_force", "cred_access", u, [e + 1])
        target, t0 = rng.choice(hosts), e * cfg.epoch_len + rng.random() * cfg.epoch_len * 0.5
        for i in range(60):
            events.append(_event(rng, t0 + i * 5, "auth", "auth_fail", u, target, gt.attack_id))
        for i in range(5):
            events.append(_event(rng, t0 + i * 60, "ids", "ids_alert", u, target, gt.attack_id))
        truth.append(gt)

    for k in range(cfg.n_low_and_slow):
        u = next(it)
        start = rng.randrange(0, max(1, cfg.epochs - cfg.lns_epochs))
        gt = GroundTruth(f"lns{k}", "low_and_slow", "cred_access", u, [])
        for e in range(start, min(cfg.epochs, start + cfg.lns_epochs)):
            gt.epochs.append(e + 1)
            for _ in range(cfg.lns_per_epoch):
                ts = e * cfg.epoch_len + rng.random() * cfg.epoch_len
                events.append(_event(rng, ts, "auth", "auth_fail", u, rng.choice(hosts), gt.attack_id))
        truth.append(gt)

    for k in range(cfg.n_exfil):
        u = next(it)
        start = rng.randrange(0, max(1, cfg.epochs - 3))
        gt = GroundTruth(f"exf{k}", "exfil", "exfil", u, [])
        dest = rng.choice(external)
        for e in range(start, min(cfg.epochs, start + 3)):
            gt.epochs.append(e + 1)
            for _ in range(12):
                ts = e * cfg.epoch_len + rng.random() * cfg.epoch_len
                events.append(_event(rng, ts, "web", "data_transfer", u, dest, gt.attack_id, rng.randint(400, 900)))
        truth.append(gt)

    for k in range(cfg.n_coordinated):
        u, e = next(it), rng.randrange(1, cfg.epochs)
        gt = GroundTruth(f"co{k}", "coordinated", "multi_source", u, [e + 1])
        t0 = e * cfg.epoch_len
        for src, cat in (("auth", "auth_fail"), ("fw", "conn_denied"), ("ids", "ids_alert")):
            for _ in range(cfg.coord_per_source):
                events.append(_event(rng, t0 + rng.random() * cfg.epoch_len, src, cat, u,
                                     rng.choice(hosts), gt.attack_id))
        truth.append(gt)

    events.sort(key=lambda ev: ev.ts)
    return events, truth


def default_profiles_and_contexts() -> tuple[list[AttackProfile], list[Context]]:
    """Profiles and contexts matching the synthetic attack classes.

    Graph features: (weighted_degree, resource_diversity, source_diversity, relations,
    temporal_dispersion). One context slot per class. Theta is calibrated on padded
    streams (Phase 1, Step 5) -- tune it in E1/E4.
    """
    contexts = [
        Context("q_auth_fail", "cred_access", categories=frozenset({"auth_fail"}),
                feats=("count",), policy=Policy.VALUE),
        Context("q_transfer", "exfil", categories=frozenset({"data_transfer"}),
                feats=("bytes",), policy=Policy.DECISION, threshold=1000),
        Context("q_multi", "multi_source", categories=frozenset({"auth_fail", "conn_denied", "ids_alert"}),
                feats=("count",), policy=Policy.HIDE),
    ]
    profiles = [
        AttackProfile("cred_access", frozenset({"auth_fail"}),
                      theta_g=(1.0, 0.5, 0.0, 0.0, 0.2), theta_y=(0.0,), theta_h=2.0, Theta=20.0, kappa=0.3),
        AttackProfile("exfil", frozenset({"data_transfer"}),
                      theta_g=(1.0, 0.0, 0.0, 0.0, 0.3), theta_y=(0.0,), theta_h=2.0, Theta=25.0, kappa=0.3),
        AttackProfile("multi_source", frozenset({"auth_fail", "conn_denied", "ids_alert"}),
                      theta_g=(0.3, 0.2, 4.0, 0.2, 0.0), theta_y=(0.0,), theta_h=0.5, Theta=15.0, kappa=0.3),
    ]
    return profiles, contexts
