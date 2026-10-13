"""Fetch the raw Kyoto 2016 yearly archive (for B6, Ogawa et al.) into ~/data/kyoto2016-raw.

takakura.com/Kyoto_data is no longer reachable; the Internet Archive holds a copy of
new_data201704/2015/2015.zip (2.6 GB; one tab-separated file per day, 24 fields). It is the
only year archived. The AnoShift benchmark's Kyoto 2016 release is not usable for B6: its
numeric features are pre-binned and IPs, ports and start times are dropped.

Usage:  python tools/kyoto_fetch.py
"""

from __future__ import annotations

import argparse
import subprocess
import zipfile
from pathlib import Path

URL = ("https://web.archive.org/web/20250808091743id_/"
       "http://www.takakura.com/Kyoto_data/new_data201704/2015/2015.zip")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dest", default="~/data/kyoto2016-raw")
    args = ap.parse_args()
    dest = Path(args.dest).expanduser()
    dest.mkdir(parents=True, exist_ok=True)
    out = dest / "2015.zip"
    if not (out.exists() and zipfile.is_zipfile(out)):   # complete: the central directory is at the end
        subprocess.run(["curl", "-sSfL", "-C", "-", "--retry", "5", "-o", str(out), URL], check=True)
    with zipfile.ZipFile(out) as z:
        names = [n for n in z.namelist() if n.endswith(".txt")]
    print(f"{out}: {out.stat().st_size / 2**30:.2f} GB, {len(names)} daily files")


if __name__ == "__main__":
    main()
