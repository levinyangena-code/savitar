"""In-memory graph with typed nodes, typed edges, and evidence on every edge.

This is the defensive-analytics substrate. It is deliberately small and
deterministic so tests are reproducible. Production deployments would back
this with Neo4j / TigerGraph / Kuzu; the QueryEngine is graph-agnostic and
reads via the ``neighbors()`` / ``node()`` interface below.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Iterator

from .evidence import Evidence, DEFAULT_RULE_VERSION, SCORING_MODEL_VERSION

NOW = datetime(2026, 10, 23, 12, 0, 0, tzinfo=timezone.utc)  # reference "today"


@dataclass
class Node:
    id: str
    type: str                       # asset | identity | vulnerability | actor | incident | ioc
    attrs: dict[str, Any] = field(default_factory=dict)

    @property
    def cvss(self) -> float:            return float(self.attrs.get("cvss", 0.0))
    @property
    def in_kev(self) -> bool:           return bool(self.attrs.get("in_kev", False))
    @property
    def criticality(self) -> str:       return self.attrs.get("criticality", "medium")
    @property
    def privilege_score(self) -> float: return float(self.attrs.get("privilege_score", 0.3))
    @property
    def threat_level(self) -> float:    return float(self.attrs.get("threat_level", 5.0))
    @property
    def business_unit(self) -> str:     return self.attrs.get("business_unit", "unknown")
    @property
    def exposed(self) -> bool:          return bool(self.attrs.get("exposed", False))
    @property
    def ttps(self) -> list[str]:        return list(self.attrs.get("ttps", []))
    @property
    def mfa(self) -> bool:              return bool(self.attrs.get("mfa", False))


@dataclass
class Edge:
    src: str
    dst: str
    relation: str
    evidence: Evidence
    weight: float = 1.0


class Graph:
    def __init__(self) -> None:
        self._nodes: dict[str, Node] = {}
        self._fwd: dict[str, list[Edge]] = {}
        self._rev: dict[str, list[Edge]] = {}

    def add_node(self, node: Node) -> None:
        self._nodes[node.id] = node

    def add_edge(self, edge: Edge) -> None:
        self._fwd.setdefault(edge.src, []).append(edge)
        self._rev.setdefault(edge.dst, []).append(edge)

    def node(self, nid: str) -> Node | None:
        return self._nodes.get(nid)

    def nodes(self) -> Iterable[Node]:
        return self._nodes.values()

    def neighbors(self, nid: str) -> Iterator[tuple[Edge, Node, str]]:
        for e in self._fwd.get(nid, []):
            n = self._nodes.get(e.dst)
            if n:
                yield e, n, "out"
        for e in self._rev.get(nid, []):
            n = self._nodes.get(e.src)
            if n:
                yield e, n, "in"

    def edges(self) -> Iterable[Edge]:
        for lst in self._fwd.values():
            yield from lst

    def __len__(self) -> int:
        return len(self._nodes)


def _ev(source: str, days_ago: float, hint: float = 0.9) -> Evidence:
    return Evidence(
        source=source,
        timestamp=NOW - timedelta(days=days_ago),
        rule_version=DEFAULT_RULE_VERSION,
        model_version=SCORING_MODEL_VERSION,
        confidence_hint=hint,
    )


def build_sample_graph(seed: int = 42) -> Graph:
    """Build a small, deterministic graph for tests and demos."""
    rng = random.Random(seed)
    g = Graph()

    assets = [
        Node("asset:web-prod-01", "asset", {"criticality": "critical", "exposed": True,
             "business_unit": "payments", "os": "linux", "service": "nginx/1.25"}),
        Node("asset:web-prod-02", "asset", {"criticality": "critical", "exposed": True,
             "business_unit": "payments", "os": "linux", "service": "nginx/1.25"}),
        Node("asset:db-prod-01",  "asset", {"criticality": "critical", "exposed": False,
             "business_unit": "payments", "os": "linux", "service": "postgres/15"}),
        Node("asset:hr-app-01",   "asset", {"criticality": "high", "exposed": True,
             "business_unit": "hr", "os": "windows", "service": "iis/10"}),
        Node("asset:ot-plc-01",   "asset", {"criticality": "critical", "exposed": False,
             "business_unit": "manufacturing", "os": "vendor-rtos", "service": "plc-fw/3.2"}),
        Node("asset:dev-ws-07",   "asset", {"criticality": "low", "exposed": False,
             "business_unit": "engineering", "os": "macos", "service": "ssh"}),
    ]
    for a in assets:
        g.add_node(a)

    identities = [
        Node("id:svc-payments", "identity", {"privilege_score": 0.8, "mfa": False,
             "business_unit": "payments", "kind": "service_account"}),
        Node("id:svc-deploy",   "identity", {"privilege_score": 0.9, "mfa": False,
             "business_unit": "engineering", "kind": "service_account"}),
        Node("id:alice",        "identity", {"privilege_score": 0.4, "mfa": True,
             "business_unit": "payments", "kind": "user"}),
        Node("id:bob",          "identity", {"privilege_score": 0.3, "mfa": True,
             "business_unit": "hr", "kind": "user"}),
    ]
    for i in identities:
        g.add_node(i)

    vulns = [
        Node("vuln:CVE-2026-1001", "vulnerability", {"cvss": 9.8, "in_kev": True,
             "epss": 0.87, "exploit_maturity": "weaponized", "cpe": "nginx:1.25"}),
        Node("vuln:CVE-2026-1002", "vulnerability", {"cvss": 7.5, "in_kev": False,
             "epss": 0.32, "exploit_maturity": "poc", "cpe": "postgres:15"}),
        Node("vuln:CVE-2026-2001", "vulnerability", {"cvss": 8.1, "in_kev": True,
             "epss": 0.71, "exploit_maturity": "weaponized", "cpe": "iis:10"}),
        Node("vuln:CVE-2026-3001", "vulnerability", {"cvss": 6.5, "in_kev": False,
             "epss": 0.11, "exploit_maturity": "functional", "cpe": "plc-fw:3.2"}),
    ]
    for v in vulns:
        g.add_node(v)

    actors = [
        Node("actor:TEMP-REVE", "actor", {"threat_level": 8.5, "aliases": ["REVE-RaaS"],
             "family": "ransomware", "ttps": ["T1190", "T1078", "T1486"]}),
        Node("actor:APT-SABLE", "actor", {"threat_level": 9.2, "aliases": ["SABLE-Group"],
             "family": "espionage", "ttps": ["T1190", "T1059", "T1071"]}),
    ]
    for a in actors:
        g.add_node(a)

    iocs = [
        Node("ioc:sha256:deadbeef", "ioc", {"kind": "file_hash", "malware_family": "REVE"}),
        Node("ioc:domain:bad.example", "ioc", {"kind": "domain", "malware_family": "REVE"}),
    ]
    for i in iocs:
        g.add_node(i)

    incidents = [
        Node("inc:2026-09-12", "incident", {"severity": "high",
             "ttps": ["T1190", "T1078"], "business_unit": "payments"}),
        Node("inc:2026-08-04", "incident", {"severity": "medium",
             "ttps": ["T1190", "T1059"], "business_unit": "hr"}),
    ]
    for i in incidents:
        g.add_node(i)

    def e(src: str, dst: str, rel: str, days_ago: float,
          hint: float = 0.9, w: float = 1.0) -> None:
        g.add_edge(Edge(src, dst, rel, _ev(f"{rel}-sensor", days_ago, hint), w))

    e("asset:web-prod-01", "vuln:CVE-2026-1001", "affected_by", 2, 0.95)
    e("asset:web-prod-02", "vuln:CVE-2026-1001", "affected_by", 2, 0.95)
    e("asset:db-prod-01",  "vuln:CVE-2026-1002", "affected_by", 5, 0.85)
    e("asset:hr-app-01",   "vuln:CVE-2026-2001", "affected_by", 1, 0.92)
    e("asset:ot-plc-01",   "vuln:CVE-2026-3001", "affected_by", 14, 0.70)
    e("id:svc-payments", "asset:web-prod-01", "runs_on", 0.5, 0.99)
    e("id:svc-payments", "asset:web-prod-02", "runs_on", 0.5, 0.99)
    e("id:svc-payments", "asset:db-prod-01",  "authenticates_to", 0.5, 0.99)
    e("id:svc-deploy",   "asset:web-prod-01", "runs_on", 1, 0.95)
    e("id:svc-deploy",   "asset:web-prod-02", "runs_on", 1, 0.95)
    e("id:svc-deploy",   "asset:hr-app-01",   "runs_on", 1, 0.95)
    e("id:alice",        "asset:web-prod-01", "authenticates_to", 0.2, 0.90)
    e("id:bob",          "asset:hr-app-01",   "authenticates_to", 0.3, 0.90)
    e("actor:TEMP-REVE", "vuln:CVE-2026-1001", "exploits", 3, 0.88)
    e("actor:TEMP-REVE", "vuln:CVE-2026-2001", "exploits", 6, 0.80)
    e("actor:APT-SABLE", "vuln:CVE-2026-1001", "exploits", 10, 0.75)
    e("ioc:sha256:deadbeef", "asset:web-prod-01", "observed_on", 0.1, 0.98)
    e("ioc:domain:bad.example", "asset:web-prod-02", "observed_on", 0.2, 0.96)
    e("inc:2026-09-12", "asset:web-prod-01", "targeted", 40, 0.85)
    e("inc:2026-09-12", "actor:TEMP-REVE",   "attributed_to", 40, 0.70)
    e("inc:2026-08-04", "asset:hr-app-01",   "targeted", 80, 0.80)
    e("inc:2026-08-04", "actor:APT-SABLE",   "attributed_to", 80, 0.65)
    e("asset:web-prod-01", "ioc:domain:bad.example", "contacted", 0.05, 0.99)
    e("asset:dev-ws-07",   "ioc:domain:bad.example", "contacted", 30, 0.40)

    for _ in range(15):
        src = rng.choice([n.id for n in assets + identities])
        dst = rng.choice([n.id for n in assets + vulns])
        if src != dst:
            e(src, dst, "related_to", rng.uniform(0.1, 60), rng.uniform(0.4, 0.9))

    return g
