"""Loader for the AIT Log Data Set V2.0 (AIT-LDSv2) [Landauer et al., Zenodo 5789064].

Fetch the text logs and labels first with `tools/ait_fetch.py`. A scenario directory holds
`dataset.yaml`, `gather/<host>/logs/...`, and `labels/<host>/logs/...`, where every label
file is JSONL of {"line": n, "labels": [...]} referring to line n of the gathered file.

Normalization into L_i = (s, u, r, c, x, p, t) (Phase 1, eq:event) is a function of the
log line only. The categories are generic SIEM decoder rules (e.g. long DNS query names,
long URL queries), not dataset-specific rules:

  source  entity u           resource r              categories
  web     client IP          virtual host            http_<METHOD>_<2xx..5xx>[_lq]
  dns     client IP          registered domain       dns_q, dns_q_long
  vpn     certificate name   "vpn"                   vpn_connect, vpn_fail
  auth    account            host                    auth_fail, auth_success, su, su_fail, sudo_cmd
  audit   account / host     executable / unit       audit_auth, audit_auth_fail, audit_cmd, svc_start
  mail    sender address     recipient domain        mail_in
  ids     source IP          destination IP          ids_p1, ids_p2, ids_p3

Ground truth: labeled lines carry `Event.label` (the label set); incidents are grouped by
attack class and entity:
  dns_exfil   dnsteal
  web_attack  webshell_upload, webshell_cmd
  priv_esc    escalate, attacker_change_user, escalated_*
  recon       dns_scan, network_scan, service_scan, dirb, wpscan, traceroute, dns_brute_force
Other attacker lines (VPN foothold) keep their label but form no incident class.
"""

from __future__ import annotations

import json
import pickle
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from ..model import AttackProfile, Context, Event, Policy
from .synth import GroundTruth

CLASSES = ["recon", "web_attack", "priv_esc", "dns_exfil"]
CLASS_OF_LABEL = [  # priority order
    ("dns_exfil", {"dnsteal"}),
    ("web_attack", {"webshell_upload", "webshell_cmd"}),
    ("priv_esc", {"escalate", "attacker_change_user", "escalated_command", "escalated_sudo_command",
                  "escalated_sudo_session"}),
    ("recon", {"dns_scan", "network_scan", "service_scan", "dirb", "wpscan", "traceroute", "dns_brute_force"}),
]
MON = {m: i + 1 for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split())}

_SYSLOG = re.compile(r"^(\w{3}) +(\d+) (\d\d):(\d\d):(\d\d) (\S+) ")
_APACHE = re.compile(r'^(\S+) \S+ \S+ \[(\d+)/(\w+)/(\d+):(\d+):(\d+):(\d+) [^\]]+\] "(\S+) ([^ "]*)[^"]*" (\d{3}) (\S+)')
_DNSQ = re.compile(r"query\[(\w+)\] (\S+) from (\S+)")
_VPN = re.compile(r"^(\d+)-(\d+)-(\d+) (\d+):(\d+):(\d+) (.*)$")
_AUDIT = re.compile(r"^type=(\w+) msg=audit\((\d+\.\d+):\d+\): (.*)$")
_EXIM = re.compile(r"^(\d+)-(\d+)-(\d+) (\d+):(\d+):(\d+) \S+ <= (\S+) .*? S=(\d+)")
_FAST = re.compile(r"^(\d+)/(\d+)/(\d+)-(\d+):(\d+):(\d+)\.\d+ .*\[Priority: (\d)\] \{\w+\} ([\d.]+):?\d* -> ([\d.]+)")


def _ts(y, mo, d, h, mi, s) -> float:
    return datetime(int(y), int(mo), int(d), int(h), int(mi), int(s), tzinfo=timezone.utc).timestamp()


def _domain(name: str) -> str:
    parts = name.rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else name


# ------------------------------------------------------------------ per-format parsers
# Each returns (ts, src, user, res, cat, feats) or None for lines that carry no event.

def _p_apache(line, year, host):
    m = _APACHE.match(line)
    if not m:
        return None
    ip, d, mo, y, h, mi, s, meth, url, status, size = m.groups()
    meth = meth if meth in ("GET", "POST", "HEAD") else "OTHER"
    q = url.split("?", 1)[1] if "?" in url else ""
    cat = f"http_{meth}_{status[0]}xx" + ("_lq" if len(q) > 100 else "")
    kb = int(size) // 1024 if size.isdigit() else 0
    return _ts(y, MON[mo], d, h, mi, s), "web", ip, host, cat, {"count": 1, "bytes": kb}


def _p_dns(line, year, host):
    m = _SYSLOG.match(line)
    q = _DNSQ.search(line)
    if not (m and q):
        return None
    mo, d, h, mi, s, _ = m.groups()
    _, name, ip = q.groups()
    cat = "dns_q_long" if len(name) > 60 else "dns_q"
    return _ts(year, MON[mo], d, h, mi, s), "dns", ip, _domain(name), cat, {"count": 1}


def _p_vpn(line, year, host):
    m = _VPN.match(line)
    if not m:
        return None
    y, mo, d, h, mi, s, rest = m.groups()
    if "Peer Connection Initiated" in rest:
        user = re.search(r"\[([^\]]+)\] Peer", rest)
        return _ts(y, mo, d, h, mi, s), "vpn", user.group(1) if user else "?", "vpn", "vpn_connect", {"count": 1}
    if "AUTH_FAILED" in rest or "TLS Error" in rest or "VERIFY ERROR" in rest:
        return _ts(y, mo, d, h, mi, s), "vpn", rest.split(" ", 1)[0].split(":")[0], "vpn", "vpn_fail", {"count": 1}
    return None


def _p_auth(line, year, host):
    m = _SYSLOG.match(line)
    if not m:
        return None
    mo, d, h, mi, s, hostname = m.groups()
    t = _ts(year, MON[mo], d, h, mi, s)
    if "Failed password" in line or "authentication failure" in line:
        u = re.search(r"for (?:invalid user )?(\S+)|user=(\S+)", line)
        return t, "auth", (u.group(1) or u.group(2)) if u else "?", hostname, "auth_fail", {"count": 1}
    if "Accepted " in line:
        u = re.search(r"for (\S+)", line)
        return t, "auth", u.group(1) if u else "?", hostname, "auth_success", {"count": 1}
    if "Successful su for" in line:
        u = re.search(r"by (\S+)", line)
        return t, "auth", u.group(1) if u else "?", hostname, "su", {"count": 1}
    if "FAILED su" in line:
        u = re.search(r"by (\S+)", line)
        return t, "auth", u.group(1) if u else "?", hostname, "su_fail", {"count": 1}
    if " sudo: " in line and "COMMAND=" in line:
        u = re.search(r"sudo: +(\S+) :", line)
        return t, "auth", u.group(1) if u else "?", hostname, "sudo_cmd", {"count": 1}
    return None


def _p_audit(line, year, host):
    m = _AUDIT.match(line)
    if not m:
        return None
    typ, t, rest = m.groups()
    acct = re.search(r'acct="?([^" ]+)', rest)
    exe = re.search(r'exe="([^"]+)"', rest)
    res = exe.group(1).rsplit("/", 1)[-1] if exe else host
    if typ == "USER_AUTH":
        cat = "audit_auth_fail" if "res=failed" in rest else "audit_auth"
    elif typ == "USER_CMD":
        cat = "audit_cmd"
    elif typ == "SERVICE_START":
        unit = re.search(r"unit=(\S+)", rest)
        return float(t), "audit", f"host:{host}", unit.group(1) if unit else "?", "svc_start", {"count": 1}
    else:
        return None
    return float(t), "audit", acct.group(1) if acct else f"host:{host}", res, cat, {"count": 1}


def _p_exim(line, year, host):
    m = _EXIM.match(line)
    if not m:
        return None
    y, mo, d, h, mi, s, sender, size = m.groups()
    to = re.search(r" for (\S+)", line)
    dom = to.group(1).split("@")[-1] if to else "?"
    return _ts(y, mo, d, h, mi, s), "mail", sender, dom, "mail_in", {"count": 1, "bytes": int(size) // 1024}


def _p_fast(line, year, host):
    m = _FAST.match(line)
    if not m:
        return None
    mo, d, y, h, mi, s, prio, sip, dip = m.groups()
    return _ts(y, mo, d, h, mi, s), "ids", sip, dip, f"ids_p{prio}", {"count": 1}


def _parser_for(rel: str):
    name = rel.rsplit("/", 1)[-1]
    if "/apache2/" in rel and "access" in name or "/horde/horde-access" in rel:
        return _p_apache
    if name == "dnsmasq.log":
        return _p_dns
    if name == "openvpn.log":
        return _p_vpn
    if name.startswith("auth.log"):
        return _p_auth
    if rel.endswith("audit/audit.log"):
        return _p_audit
    if "/exim4/mainlog" in rel:
        return _p_exim
    if name == "fast.log":
        return _p_fast
    return None


def _class_of(labels: list[str]) -> str | None:
    s = set(labels)
    for cls, names in CLASS_OF_LABEL:
        if s & names:
            return cls
    return None


# ------------------------------------------------------------------ scenario loading
def load_scenario(root: str | Path, epoch_len: float = 3600.0, cache: bool = True
                  ) -> tuple[list[Event], list[GroundTruth], dict]:
    """Events (timestamps in seconds from the scenario start), incidents, and metadata."""
    root = Path(root).expanduser()
    cache_file = root / f".siemcrypt_events_{int(epoch_len)}.pkl"
    sig = sorted((str(p.relative_to(root)), p.stat().st_size)
                 for d in ("gather", "labels") for p in (root / d).rglob("*") if p.is_file())
    if cache and cache_file.exists():
        with cache_file.open("rb") as f:
            cached_sig, out = pickle.load(f)
        if cached_sig == sig:  # rebuilt whenever a log or label file changes
            return out
    meta = dict(name=root.name)
    for line in (root / "dataset.yaml").read_text().splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            meta[k.strip()] = v.strip().strip("'\"")
    start = datetime.fromisoformat(meta["start"]).replace(tzinfo=timezone.utc).timestamp()
    end = datetime.fromisoformat(meta["end"]).replace(tzinfo=timezone.utc).timestamp()
    year = int(meta["start"][:4])

    events: list[Event] = []
    counts = defaultdict(int)
    for path in sorted((root / "gather").glob("*/logs/**/*")):
        if not path.is_file():
            continue
        rel = str(path.relative_to(root / "gather"))
        parse = _parser_for(rel)
        if parse is None:
            continue
        host = rel.split("/", 1)[0]
        lab_file = root / "labels" / rel
        labels = {}
        if lab_file.exists():
            for ln in lab_file.read_text().splitlines():
                rec = json.loads(ln)
                labels[rec["line"]] = rec["labels"]
        with path.open(errors="replace") as f:
            for n, line in enumerate(f, 1):
                ev = parse(line.rstrip("\n"), year, host)
                if ev is None:
                    continue
                t, src, user, res, cat, feats = ev
                if not start <= t < end:
                    continue
                lab = labels.get(n)
                events.append(Event(src, user, res, cat, feats, line.encode()[:512], t - start,
                                    "|".join(sorted(lab)) if lab else None))
                counts[src] += 1
    events.sort(key=lambda e: e.ts)
    meta["events_by_source"] = dict(counts)
    meta["epochs"] = int((end - start) // epoch_len)
    truth = incidents(events, epoch_len)
    out = (events, truth, meta)
    if cache:
        with cache_file.open("wb") as f:
            pickle.dump((sig, out), f)
    return out


def incidents(events: list[Event], epoch_len: float) -> list[GroundTruth]:
    """One incident per (attack class, entity) with the epochs in which it is labeled."""
    eps = defaultdict(set)
    for ev in events:
        if ev.label:
            cls = _class_of(ev.label.split("|"))
            if cls:
                eps[(cls, ev.user)].add(int(ev.ts // epoch_len) + 1)
    return [GroundTruth(f"{cls}:{user}", cls, cls, user, sorted(e)) for (cls, user), e in sorted(eps.items())]


def attack_entities(events: list[Event]) -> set[str]:
    return {ev.user for ev in events if ev.label}


# ------------------------------------------------------------------ profiles and contexts
def ait_profiles_and_contexts() -> tuple[list[AttackProfile], list[Context]]:
    """One context and one graph profile per AIT attack class (weights are learned in E1)."""
    cats = {
        "recon": {"http_GET_4xx", "http_HEAD_4xx", "http_OTHER_4xx", "http_GET_3xx", "ids_p1", "ids_p2", "ids_p3",
                  "vpn_fail"},
        "web_attack": {"http_POST_2xx", "http_GET_2xx_lq", "http_POST_2xx_lq", "http_GET_5xx", "http_POST_5xx"},
        "priv_esc": {"su", "su_fail", "sudo_cmd", "audit_auth", "audit_auth_fail", "audit_cmd", "auth_fail"},
        "dns_exfil": {"dns_q_long"},
    }
    feats = {"recon": ("count",), "web_attack": ("count", "bytes"), "priv_esc": ("count",), "dns_exfil": ("count",)}
    contexts = [Context(f"q_{a}", a, categories=frozenset(c), feats=feats[a], policy=Policy.VALUE)
                for a, c in cats.items()]
    profiles = [AttackProfile(a, frozenset(c), theta_g=(1.0, 0.5, 0.5, 0.5, 0.2), theta_y=(0.0,), theta_h=1.0,
                              Theta=10.0, kappa=0.3) for a, c in cats.items()]
    return profiles, contexts


# ------------------------------------------------------------------ attack injection
def benign_background(events: list[Event], max_epoch: int | None = None, epoch_len: float = 3600.0) -> list[Event]:
    """Events without attack labels (and optionally only the first max_epoch epochs)."""
    return [ev for ev in events if not ev.label and (max_epoch is None or ev.ts < max_epoch * epoch_len)]


def pick_entity(events: list[Event], src: str, lo: int, hi: int, seed: int) -> str:
    """A benign entity of source `src` with between lo and hi events (a quiet, real host)."""
    import random

    n = defaultdict(int)
    for ev in events:
        if ev.src == src and not ev.label:
            n[ev.user] += 1
    cands = sorted(u for u, c in n.items() if lo <= c <= hi)
    if not cands:
        cands = sorted(n, key=lambda u: n[u])[: max(1, len(n) // 4)]
    if not cands:  # no benign entity of this source in the window: any quiet benign entity
        m = defaultdict(int)
        for ev in events:
            if not ev.label:
                m[ev.user] += 1
        cands = sorted(m, key=lambda u: (m[u], u))[: max(1, len(m) // 4)] or ["10.0.0.250"]
    return random.Random(seed).choice(sorted(cands))


INJECT_FAMILIES = {
    # family: (source, category, resource, entity source)
    "dns_exfil": ("dns", "dns_q_long", "exfil-cdn.net", "dns"),
    "recon": ("web", "http_GET_4xx", None, "web"),
}


def inject(events: list[Event], family: str, rate: int, span: int, start_epoch: int, seed: int,
           epoch_len: float = 3600.0, entity: str | None = None) -> tuple[list[Event], GroundTruth]:
    """Low-and-slow attack: `rate` events per epoch for `span` epochs from `start_epoch`,
    by one quiet benign entity, at uniformly random times within each epoch."""
    import random

    rng = random.Random(seed)
    src, cat, res, esrc = INJECT_FAMILIES[family]
    if entity is None:
        entity = pick_entity(events, esrc, 5, 200, seed)
    if res is None:
        hosts = sorted({ev.res for ev in events if ev.src == "web"})
        res = rng.choice(hosts)
    new, eps = [], []
    for e in range(start_epoch, start_epoch + span):
        eps.append(e)
        for _ in range(rate):
            t = (e - 1) * epoch_len + rng.random() * epoch_len
            path = "/" + "".join(rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(8))
            payload = (f"injected {family} {entity} {res}{path}").encode()
            new.append(Event(src, entity, res, cat, {"count": 1, "bytes": 0}, payload, t, f"inj_{family}"))
    gt = GroundTruth(f"inj:{family}:{entity}", family, family, entity, eps)
    return sorted(events + new, key=lambda ev: ev.ts), gt
