"""Fetch the CSE-CIC-IDS2018 processed flow CSVs (10 files, about 6.5 GB) from the dataset's
public S3 bucket into ~/data/cse-cic-ids2018 (for B4, Wingarz et al.). Rerun to resume.

Usage:  python tools/cicids2018_fetch.py [--only Thursday-01-03-2018] [--dest DIR]
"""

from __future__ import annotations

import argparse
import re
import urllib.parse
import urllib.request
from pathlib import Path

BUCKET = "https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/"
PREFIX = "Processed Traffic Data for ML Algorithms/"


def listing() -> list[tuple[str, int]]:
    url = BUCKET + "?list-type=2&prefix=" + urllib.parse.quote(PREFIX)
    xml = urllib.request.urlopen(url, timeout=60).read().decode()
    return [(k, int(s)) for k, s in re.findall(r"<Key>([^<]+)</Key>.*?<Size>(\d+)</Size>", xml) if k.endswith(".csv")]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dest", default="~/data/cse-cic-ids2018")
    ap.add_argument("--only", default=None, help="substring of the file names to fetch")
    args = ap.parse_args()
    dest = Path(args.dest).expanduser()
    dest.mkdir(parents=True, exist_ok=True)
    for key, size in listing():
        name = key.rsplit("/", 1)[-1]
        if args.only and args.only not in name:
            continue
        out = dest / name
        if out.exists() and out.stat().st_size == size:
            print(f"have {name}")
            continue
        print(f"fetching {name} ({size / 2**20:,.0f} MB)", flush=True)
        tmp = out.with_suffix(".part")
        urllib.request.urlretrieve(BUCKET + urllib.parse.quote(key), tmp)
        tmp.replace(out)
    print(f"done: {dest}")


if __name__ == "__main__":
    main()
