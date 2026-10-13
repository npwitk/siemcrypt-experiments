"""Fetch the text logs and labels of AIT-LDSv2 scenarios without downloading the archives.

AIT Log Data Set V2.0, Landauer et al., Zenodo 10.5281/zenodo.5789064, CC BY-NC-SA 4.0.
Each scenario is one zip of 7-27 GB, mostly packet captures. This reads the zip's central
directory and the selected members over HTTP range requests, so only the SIEM-relevant
text logs (a few MB to tens of MB per scenario) are transferred.

Usage:  python tools/ait_fetch.py [--out ~/data/ait-ldsv2] [scenario ...]
        (no scenario: all eight)
"""

from __future__ import annotations

import argparse
import io
import re
import urllib.request
import zipfile
from pathlib import Path

RECORD = "https://zenodo.org/api/records/5789064/files/{}.zip/content"
SCENARIOS = ["russellmitchell", "santos", "fox", "harrison", "wardbeck", "shaw", "wheeler", "wilson"]
KEEP = re.compile(
    r"^(dataset\.yaml"
    r"|labels/.+"
    r"|gather/attacker_0/logs/attacks\.log"
    r"|processing/config/.+"
    r"|gather/[^/]+/logs/(auth\.log(\.\d+)?|audit/audit\.log|apache2/.*access\.log(\.\d+)?"
    r"|openvpn\.log|dnsmasq\.log|exim4/mainlog(\.\d+)?|horde/horde-access\.log|suricata/fast\.log))$"
)
SKIP = re.compile(r"labels/monitoring/")  # metric labels, not used


class HttpFile(io.RawIOBase):
    def __init__(self, url: str):
        self.url = url
        with urllib.request.urlopen(urllib.request.Request(url, method="HEAD")) as r:
            self.size = int(r.headers["Content-Length"])
        self.pos = 0

    def seekable(self):
        return True

    def readable(self):
        return True

    def tell(self):
        return self.pos

    def seek(self, off, whence=0):
        self.pos = {0: off, 1: self.pos + off, 2: self.size + off}[whence]
        return self.pos

    def readinto(self, b):
        n = min(len(b), self.size - self.pos)
        if n <= 0:
            return 0
        req = urllib.request.Request(self.url, headers={"Range": f"bytes={self.pos}-{self.pos + n - 1}"})
        with urllib.request.urlopen(req) as r:
            data = r.read()
        b[: len(data)] = data
        self.pos += len(data)
        return len(data)


def fetch(scenario: str, out: Path) -> None:
    done = out / scenario / ".complete"
    if done.exists():   # no network once fetched (a Zenodo outage stopped a full run)
        print(f"{scenario}: already fetched", flush=True)
        return
    z = zipfile.ZipFile(io.BufferedReader(HttpFile(RECORD.format(scenario)), buffer_size=8 << 20))
    members = [i for i in z.infolist() if not i.is_dir() and KEEP.match(i.filename) and not SKIP.match(i.filename)]
    total = sum(i.compress_size for i in members)
    print(f"{scenario}: {len(members)} files, {total / 1e6:.1f} MB to transfer", flush=True)
    for i in members:
        dst = out / scenario / i.filename
        if dst.exists() and dst.stat().st_size == i.file_size:
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        with z.open(i) as src, open(dst, "wb") as f:
            while chunk := src.read(8 << 20):
                f.write(chunk)
    done.write_text("")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("scenarios", nargs="*", default=SCENARIOS)
    ap.add_argument("--out", default=str(Path.home() / "data" / "ait-ldsv2"))
    args = ap.parse_args()
    for s in args.scenarios:
        fetch(s, Path(args.out).expanduser())


if __name__ == "__main__":
    main()
