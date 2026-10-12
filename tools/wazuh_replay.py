"""B1 with real Wazuh: replay AIT-LDSv2 log lines through a Wazuh 4.8 manager with its
default decoders and rules, and score the alerts like every other system (ait_eval E1-A).

Why logtest and libfaketime: Wazuh's frequency/timeframe rules (e.g. 5712 SSH brute force,
31151 many web 400 errors) correlate on the manager's clock, not on the log's timestamp, so
replaying days of logs in minutes would break them. wazuh-analysisd therefore runs under
libfaketime with an offset read from a file on every clock call, and this script sends one
event at a time to the logtest socket (synchronous, one session that keeps the correlation
state), setting the offset so that the manager's clock equals the event's log time.

Setup on the evaluation VM (Ubuntu 24.04; once):
  sudo bash tools/wazuh_setup.sh
Run (sequential: the faked clock is global to wazuh-analysisd):
  sudo -E python tools/wazuh_replay.py --scenarios harrison,wardbeck,shaw,wheeler,wilson
Writes results/wazuh_alerts_<scenario>.jsonl (one line per alert) and
results/wazuh_e1.csv / wazuh_e1.md with the E1-A metrics of "B1-wazuh".

Class mapping (ours; Wazuh has no attack-class labels): an alert counts for a class if
its rule groups intersect the class's group set below. Wazuh's default rules have no DNS
exfiltration rule, so dns_exfil gets no alerts.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import struct
import sys
import time
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "experiments"))

from siemcrypt.data.ait import CLASSES, load_scenario  # noqa: E402

SOCKET = "/var/ossec/queue/sockets/logtest"
FAKETIME_FILE = "/var/ossec/tmp/faketime"
LOG_FORMAT = {"web": "apache", "audit": "audit"}           # everything else: syslog
LOCATION = {"web": "/var/log/apache2/access.log", "dns": "/var/log/dnsmasq.log", "vpn": "/var/log/openvpn.log",
            "auth": "/var/log/auth.log", "audit": "/var/log/audit/audit.log", "mail": "/var/log/exim4/mainlog",
            "ids": "/var/log/suricata/fast.log"}
CLASS_GROUPS = {
    "recon": {"web_scan", "recon", "scan", "ids", "network_scan"},
    "web_attack": {"attack", "sql_injection", "web_attack", "exploit_attempt", "xss"},
    "priv_esc": {"sudo", "su", "privilege_escalation", "audit_command"},
    "dns_exfil": set(),
}
ALERT_LEVEL = 3  # Wazuh's default log_alert_level


class LogTest:
    """Client for the wazuh-logtest socket (4-byte little-endian length + JSON)."""

    def __init__(self, path: str = SOCKET):
        self.path, self.token = path, None

    def _call(self, msg: dict) -> dict:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(self.path)
        data = json.dumps(msg).encode()
        s.sendall(struct.pack("<I", len(data)) + data)
        n = struct.unpack("<I", self._recv(s, 4))[0]
        out = json.loads(self._recv(s, n))
        s.close()
        return out

    @staticmethod
    def _recv(s, n):
        buf = b""
        while len(buf) < n:
            chunk = s.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("logtest socket closed")
            buf += chunk
        return buf

    def process(self, line: str, log_format: str, location: str) -> dict:
        p = {"event": line, "log_format": log_format, "location": location}
        if self.token:
            p["token"] = self.token
        out = self._call({"version": 1, "origin": {"name": "siemcrypt", "module": "replay"},
                          "command": "log_processing", "parameters": p})
        data = out.get("data", {})
        self.token = data.get("token", self.token)
        return data

    def close(self):
        if self.token:
            self._call({"version": 1, "origin": {"name": "siemcrypt", "module": "replay"},
                        "command": "remove_session", "parameters": {"token": self.token}})


def set_clock(abs_ts: float) -> None:
    """libfaketime reads '+<seconds>' from FAKETIME_FILE on every clock call (NO_CACHE)."""
    tmp = FAKETIME_FILE + ".tmp"
    with open(tmp, "w") as f:
        f.write(f"{abs_ts - time.time():+.3f}\n")
    os.replace(tmp, FAKETIME_FILE)


def replay(data: Path, name: str, out: Path) -> list[dict]:
    events, truth, meta = load_scenario(data / name)
    from datetime import datetime, timezone
    start = datetime.fromisoformat(meta["start"]).replace(tzinfo=timezone.utc).timestamp()
    lt = LogTest()
    alerts = []
    t0 = time.time()
    with (out / f"wazuh_alerts_{name}.jsonl").open("w") as f:
        for i, ev in enumerate(events):
            set_clock(start + ev.ts)
            line = ev.payload.decode(errors="replace").rstrip("\n")
            res = lt.process(line, LOG_FORMAT.get(ev.src, "syslog"), LOCATION[ev.src])
            rule = res.get("output", {}).get("rule")
            if rule and int(rule.get("level", 0)) >= ALERT_LEVEL and res.get("alert", True):
                a = dict(entity=ev.user, ts=ev.ts, rule=rule.get("id"), level=int(rule["level"]),
                         groups=rule.get("groups", []), description=rule.get("description"))
                alerts.append(a)
                f.write(json.dumps(a) + "\n")
            if i % 50000 == 0:
                print(f"  {name}: {i:,}/{len(events):,} events, {len(alerts):,} alerts, {time.time() - t0:.0f}s",
                      flush=True)
    lt.close()
    return alerts


def score(name: str, alerts: list[dict], data: Path) -> list[dict]:
    from common import score_alerts, threshold_free
    events, truth, _ = load_scenario(data / name)
    epoch = 3600.0
    binary, raw = set(), defaultdict(float)
    for ev in events:  # every active (entity, epoch) is scored; no alert = level 0
        for cls in CLASSES:
            raw[(ev.user, cls, int(ev.ts // epoch) + 1)] += 0.0
    for a in alerts:
        for cls, groups in CLASS_GROUPS.items():
            if groups & set(a["groups"]):
                k = (a["entity"], cls, int(a["ts"] // epoch) + 1)
                binary.add(k)
                raw[k] = max(raw[k], a["level"])
    scores, per = score_alerts(binary, truth, CLASSES)
    tf = threshold_free(dict(raw), truth, CLASSES)
    rows = []
    for c in CLASSES:
        x = scores[c]
        rows.append(dict(system="B1-wazuh", scenario=name, attack_class=c, incidents=x.incidents, detected=x.detected,
                         false_entities=x.alerted_pairs - x.true_pairs, precision=x.precision, recall=x.recall,
                         f1=x.f1, auc=tf[c]["auc"], recall_at_fp2=tf[c]["recall_at_fp"]))
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenarios", default="harrison,wardbeck,shaw,wheeler,wilson")
    ap.add_argument("--data", default="~/data/ait-ldsv2")
    ap.add_argument("--score-only", action="store_true", help="re-score saved alert files")
    args = ap.parse_args()
    data, out = Path(args.data).expanduser(), Path(__file__).resolve().parents[1] / "results"
    out.mkdir(exist_ok=True)
    rows = []
    for name in args.scenarios.split(","):
        if args.score_only:
            alerts = [json.loads(x) for x in (out / f"wazuh_alerts_{name}.jsonl").read_text().splitlines()]
        else:
            alerts = replay(data, name, out)
        rows += score(name, alerts, data)
    from common import write_csv
    write_csv("wazuh_e1.csv", rows)
    md = ["# B1 with real Wazuh (default rules) on AIT-LDSv2\n", "| Class | Incidents | Detected | False entities | F1 | AUC | Recall@FP2 |",
          "|---|---|---|---|---|---|---|"]
    for c in CLASSES:
        sel = [r for r in rows if r["attack_class"] == c]
        aucs = [r["auc"] for r in sel if r["auc"] == r["auc"] and r["auc"] is not None]
        md.append(f"| {c} | {sum(r['incidents'] for r in sel)} | {sum(r['detected'] for r in sel)} | "
                  f"{sum(r['false_entities'] for r in sel)} | {sum(r['f1'] for r in sel) / len(sel):.3f} | "
                  f"{(sum(aucs) / len(aucs)) if aucs else float('nan'):.3f} | "
                  f"{sum(r['recall_at_fp2'] for r in sel) / len(sel):.3f} |")
    (out / "wazuh_e1.md").write_text("\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    main()
