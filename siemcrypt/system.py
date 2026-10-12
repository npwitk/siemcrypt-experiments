"""Wires the parties together and runs the epoch loop (Phases 1-5); Phase 6 is on demand."""

from __future__ import annotations

import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from .bus import Bus
from .model import AttackProfile, Config, Context, Event
from .parties.cloud import CloudSIEM
from .parties.ee import Descriptor, EdgeEncryptor
from .parties.ka import KeyAuthority
from .parties.sa import Investigation, SecurityAnalyst
from .parties.td import TokenDirectory


@dataclass
class EpochReport:
    epoch: int
    events: int
    drift: float
    alerts: list[Descriptor] = field(default_factory=list)
    releases: list[dict] = field(default_factory=list)


class SIEMCrypt:
    def __init__(self, cfg: Config, profiles: list[AttackProfile], contexts: list[Context]):
        self.cfg = cfg
        self.bus = Bus()
        self.ka = KeyAuthority(cfg)
        self.bus.ct_bytes = self.ka.pk_h.ciphertext_bytes()
        self.td = TokenDirectory()
        self.cloud = CloudSIEM(self.ka, self.bus, cfg.full_he)
        self.ee = EdgeEncryptor(cfg, self.ka, self.td, self.bus, {p.name: p for p in profiles}, contexts)
        self.sa = SecurityAnalyst(self.bus, cfg.default_lookback)
        self.ee.cloud, self.ee.sa = self.cloud, self.sa
        self.sa.ee, self.sa.cloud, self.sa.ka, self.sa.td = self.ee, self.cloud, self.ka, self.td
        self.feat_index = {f: j for j, f in enumerate(cfg.agg_features)}
        self.reports: list[EpochReport] = []
        self.timing = Counter()  # wall-clock seconds per phase group

    def epoch_of(self, ts: float) -> int:
        return int(ts // self.cfg.epoch_len) + 1

    def run(self, events: list[Event]) -> list[EpochReport]:
        by_epoch: dict[int, list[Event]] = defaultdict(list)
        for ev in sorted(events, key=lambda x: x.ts):
            by_epoch[self.epoch_of(ev.ts)].append(ev)
        for e in sorted(by_epoch):
            self.reports.append(self.run_epoch(e, by_epoch[e]))
        self.close()
        return self.reports

    def close(self) -> None:
        self.ee.he.close()

    def run_epoch(self, e: int, events: list[Event]) -> EpochReport:
        # Phases 1-2 at the EE (includes offline randomizer generation, see ee.stats)
        t0 = time.perf_counter()
        self.ee.start_epoch(e)
        for ev in events:
            self.ee.ingest(ev)
        self.ee.end_epoch()
        t1 = time.perf_counter()
        # Phase 3 (SG-HEF, incl. KA release) and Phase 4 (graph) at the cloud
        queries = self.ee.make_queries()
        self.cloud.receive_graph_profiles(e, self.ee.graph_profiles())
        Z = self.cloud.sghef(queries, self.feat_index)
        t2 = time.perf_counter()
        updates, drift = self.cloud.phase4(e, Z)
        t3 = time.perf_counter()
        # Phase 5 at the EE
        alerts = self.ee.phase5(updates, drift)
        t4 = time.perf_counter()
        self.timing.update({"phase12": t1 - t0, "phase3": t2 - t1, "phase4": t3 - t2, "phase5": t4 - t3})
        return EpochReport(e, len(events), drift, alerts, [{"qid": z["qid"], "y": z["y"], "phi": z["phi"]} for z in Z])

    def investigate(self, d: Descriptor) -> Investigation:
        return self.sa.investigate(d)
