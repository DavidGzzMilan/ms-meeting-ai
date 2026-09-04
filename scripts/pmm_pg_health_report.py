#!/usr/bin/env python3
"""
PMM v3 PostgreSQL service health scraper and report generator.

Collects inventory, advisors, QAN, and Prometheus (VictoriaMetrics) time series
for a single PostgreSQL service over a configurable UTC window (default: last 6h),
detects spikes and baseline divergence, and writes HEALTH_REPORT.md with section
grades A–F.

Auth: HTTP Basic from repo `cred` file (user:password).
Default PMM: https://127.0.0.1:18003
"""
from __future__ import annotations

import argparse
import base64
import json
import math
import os
import ssl
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import urlencode, urlparse

PG_QAN_AGENT_KINDS = (
    "qan_postgresql_pgstatements_agent",
    "qan_postgresql_pgstatmonitor_agent",
)
PG_EXPORTER_KIND = "postgres_exporter"
NODE_EXPORTER_KIND = "node_exporter"

GRADES = ("A", "B", "C", "D", "F")


def load_cred(path: Path) -> tuple[str, str]:
    raw = path.read_text(encoding="utf-8").strip().replace("\r", "")
    if ":" not in raw:
        raise SystemExit(f"cred file {path} must be user:password")
    user, _, password = raw.partition(":")
    return user, password


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def rfc3339(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds").replace("+00:00", "Z")


class PMMClient:
    def __init__(self, base_url: str, user: str, password: str) -> None:
        parsed = urlparse(base_url.rstrip("/"))
        if not parsed.scheme or not parsed.netloc:
            raise SystemExit(f"Invalid base URL: {base_url!r}")
        self._origin = f"{parsed.scheme}://{parsed.netloc}"
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        self._headers = {
            "Authorization": f"Basic {token}",
            "Accept": "application/json",
        }
        self._ctx = ssl.create_default_context()
        self._ctx.check_hostname = False
        self._ctx.verify_mode = ssl.CERT_NONE

    def request(
        self,
        method: str,
        path: str,
        *,
        query: Optional[dict[str, str]] = None,
        json_body: Any = None,
    ) -> tuple[int, Any]:
        if not path.startswith("/"):
            path = "/" + path
        url = self._origin + path
        if query:
            url += "?" + urlencode(query)
        data = None
        hdrs = dict(self._headers)
        if json_body is not None:
            data = json.dumps(json_body).encode("utf-8")
            hdrs["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        try:
            with urllib.request.urlopen(req, context=self._ctx, timeout=180) as resp:
                body = resp.read().decode("utf-8")
                status = resp.getcode() or 200
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            status = e.code
        if not body.strip():
            return status, None
        try:
            return status, json.loads(body)
        except json.JSONDecodeError:
            return status, {"_raw": body[:8000]}

    def prom_query_range(
        self, expr: str, start: int, end: int, step: int
    ) -> dict[str, Any]:
        st, data = self.request(
            "GET",
            "/prometheus/api/v1/query_range",
            query={"query": expr, "start": str(start), "end": str(end), "step": str(step)},
        )
        if st != 200 or not isinstance(data, dict):
            return {"status": "error", "http_status": st, "error": data}
        return data


def save_json(out_dir: Path, name: str, payload: Any) -> None:
    (out_dir / name).write_text(
        json.dumps(payload, indent=2, default=str), encoding="utf-8"
    )


def find_pg_service(
    client: PMMClient, target: str
) -> tuple[dict[str, Any], str]:
    status, data = client.request(
        "GET",
        "/v1/inventory/services",
        query={"service_type": "SERVICE_TYPE_POSTGRESQL_SERVICE"},
    )
    if status != 200 or not isinstance(data, dict):
        raise SystemExit(f"List services failed: HTTP {status} {data!r}")
    pg = data.get("postgresql") or []
    if not isinstance(pg, list):
        pg = []
    for svc in pg:
        if not isinstance(svc, dict):
            continue
        if svc.get("service_name") == target or svc.get("service_id") == target:
            note = (
                "matched service_name"
                if svc.get("service_name") == target
                else "matched service_id"
            )
            return svc, note
    st2, one = client.request("GET", f"/v1/inventory/services/{target}")
    if st2 == 200 and isinstance(one, dict) and one.get("postgresql"):
        m = one["postgresql"]
        if isinstance(m, dict):
            return m, "GET /v1/inventory/services/{id}"
    raise SystemExit(
        f"PostgreSQL service {target!r} not found ({len(pg)} services in inventory)."
    )


def resolve_node_name(client: PMMClient, node_id: str) -> str:
    st, data = client.request("GET", f"/v1/inventory/nodes/{node_id}")
    if st == 200 and isinstance(data, dict):
        for key in ("generic", "container", "remote", "remote_rds"):
            node = data.get(key)
            if isinstance(node, dict) and node.get("node_name"):
                return str(node["node_name"])
        for node in data.values():
            if isinstance(node, dict) and node.get("node_name"):
                return str(node["node_name"])
    return node_id


@dataclass
class SeriesStats:
    n: int = 0
    min: Optional[float] = None
    max: Optional[float] = None
    mean: Optional[float] = None
    stdev: Optional[float] = None
    last: Optional[float] = None
    max_over_mean: Optional[float] = None
    spike_z: Optional[float] = None
    note: str = ""

    @property
    def has_data(self) -> bool:
        return self.n >= 2 and self.mean is not None


def analyze_values(values: list[float]) -> SeriesStats:
    clean = [v for v in values if v is not None and not math.isnan(v)]
    if len(clean) < 2:
        return SeriesStats(n=len(clean), note="insufficient points")
    mean = sum(clean) / len(clean)
    var = sum((x - mean) ** 2 for x in clean) / max(len(clean) - 1, 1)
    stdev = math.sqrt(var)
    mx = max(clean)
    ratio = mx / mean if mean > 1e-12 else None
    z = (mx - mean) / stdev if stdev > 1e-12 else None
    return SeriesStats(
        n=len(clean),
        min=min(clean),
        max=mx,
        mean=mean,
        stdev=stdev,
        last=clean[-1],
        max_over_mean=ratio,
        spike_z=z,
    )


def _prom_range_window(step: int) -> str:
    """Prometheus range window aligned with query_range step (Grafana $interval)."""
    if step >= 3600:
        return "1h"
    if step >= 300:
        return "5m"
    if step >= 60:
        return "1m"
    return "5m"


def _longest_series_values(series_list: list[Any]) -> list[float]:
    best: list[float] = []
    for series in series_list:
        if not isinstance(series, dict):
            continue
        vals: list[float] = []
        for _, raw in series.get("values") or []:
            try:
                v = float(raw)
            except (TypeError, ValueError):
                continue
            if not math.isnan(v):
                vals.append(v)
        if len(vals) > len(best):
            best = vals
    return best


def _longest_series_pairs(series_list: list[Any]) -> list[tuple[float, float]]:
    best: list[tuple[float, float]] = []
    for series in series_list:
        if not isinstance(series, dict):
            continue
        pairs: list[tuple[float, float]] = []
        for ts, raw in series.get("values") or []:
            try:
                pairs.append((float(ts), float(raw)))
            except (TypeError, ValueError):
                continue
        if len(pairs) > len(best):
            best = pairs
    return best


def extract_range_values(prom_resp: dict[str, Any]) -> list[float]:
    """Use the longest returned series (avoids mixing hr/lr/mr scrape resolutions)."""
    return _longest_series_values(prom_resp.get("data", {}).get("result") or [])


def extract_range_series(prom_resp: dict[str, Any]) -> list[tuple[float, float]]:
    """Timestamped values from the longest returned series."""
    return _longest_series_pairs(prom_resp.get("data", {}).get("result") or [])


@dataclass
class MetricFinding:
    title: str
    expr: str
    stats: SeriesStats
    unit: str = ""
    spikes: list[str] = field(default_factory=list)
    risks: list[str] = field(default_factory=list)


@dataclass
class SectionReport:
    title: str
    grade: str
    summary: str
    findings: list[MetricFinding] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    immediate: list[str] = field(default_factory=list)


def grade_from_score(score: int) -> str:
    """Lower score is healthier. Map to letter grade."""
    if score <= 0:
        return "A"
    if score == 1:
        return "B"
    if score == 2:
        return "C"
    if score == 3:
        return "D"
    return "F"


def worst_grade(*grades: str) -> str:
    order = {g: i for i, g in enumerate(GRADES)}
    return max(grades, key=lambda g: order.get(g, 0))


def detect_spikes(
    stats: SeriesStats,
    *,
    ratio_warn: float = 4.0,
    ratio_crit: float = 10.0,
    z_warn: float = 3.0,
    z_crit: float = 5.0,
) -> tuple[list[str], int]:
    """Return spike messages and severity score increment."""
    spikes: list[str] = []
    score = 0
    if not stats.has_data:
        return spikes, score
    if stats.max_over_mean and stats.max_over_mean >= ratio_crit:
        spikes.append(
            f"sharp spike: max/mean {stats.max_over_mean:.1f}x "
            f"(max={stats.max:.4g}, mean={stats.mean:.4g})"
        )
        score += 2
    elif stats.max_over_mean and stats.max_over_mean >= ratio_warn:
        spikes.append(
            f"moderate burst: max/mean {stats.max_over_mean:.1f}x "
            f"(max={stats.max:.4g}, mean={stats.mean:.4g})"
        )
        score += 1
    if stats.spike_z and stats.spike_z >= z_crit:
        spikes.append(f"extreme outlier: z-score {stats.spike_z:.1f} on max vs window")
        score = max(score, 2)
    elif stats.spike_z and stats.spike_z >= z_warn:
        spikes.append(f"statistical outlier: z-score {stats.spike_z:.1f}")
        score = max(score, 1)
    return spikes, score


@dataclass
class PromPanel:
    key: str
    title: str
    expr: Callable[[str, str], str]
    unit: str
    grade_fn: Callable[[SeriesStats, list[str]], tuple[int, list[str], list[str]]]


def _pg(service: str) -> str:
    return f'service_name="{service}"'


def _node(node: str) -> str:
    return f'node_name="{node}"'


def build_pg_panels(service: str) -> list[PromPanel]:
    s = _pg(service)

    def grade_up(st: SeriesStats, spikes: list[str]) -> tuple[int, list[str], list[str]]:
        risks, score, imm = [], 0, []
        if st.min is not None and st.min < 0.5:
            risks.append("postgres_exporter or scrape target was down in the window")
            score += 3
            imm.append("Verify postgres_exporter / pmm-agent; check pg_up and up metrics.")
        return score, risks, imm

    def grade_connections(st: SeriesStats, spikes: list[str]) -> tuple[int, list[str], list[str]]:
        risks, score, imm = [], 0, []
        if st.max and st.max > 80:
            risks.append(f"peak connections {st.max:.0f} — validate max_connections and pool sizing")
            score += 2
        elif st.max and st.max > 40:
            risks.append(f"elevated connections (peak {st.max:.0f})")
            score += 1
        if spikes:
            score += 1
        return score, risks, imm

    def grade_tps(st: SeriesStats, spikes: list[str]) -> tuple[int, list[str], list[str]]:
        risks, score, imm = [], 0, []
        if spikes and st.max and st.mean and st.max > 5 * st.mean:
            risks.append("transaction commit rate spiked — correlate with batch jobs or deploys")
            score += 1
        return score, risks, imm

    def grade_cache(st: SeriesStats, spikes: list[str]) -> tuple[int, list[str], list[str]]:
        risks, score, imm = [], 0, []
        if st.min is not None and st.min < 0.90:
            risks.append(f"buffer cache hit ratio dropped to {st.min:.1%} — IO pressure or cold cache")
            score += 2
            imm.append("Inspect pg_stat_database blks_read, missing indexes, and shared_buffers.")
        elif st.min is not None and st.min < 0.98:
            risks.append(f"cache hit ratio briefly below 98% (min {st.min:.1%})")
            score += 1
        return score, risks, imm

    def grade_deadlocks(st: SeriesStats, spikes: list[str]) -> tuple[int, list[str], list[str]]:
        risks, score, imm = [], 0, []
        if st.max and st.max > 0:
            risks.append(f"deadlocks observed in window (max rate {st.max:.4g}/s)")
            score += 2
            imm.append("Review deadlock graphs in logs; check lock order in hot transactions.")
        return score, risks, imm

    def grade_locks(st: SeriesStats, spikes: list[str]) -> tuple[int, list[str], list[str]]:
        risks, score, imm = [], 0, []
        if st.max and st.max > 50:
            risks.append(f"high lock count peak ({st.max:.0f})")
            score += 2
        elif spikes:
            score += 1
        return score, risks, imm

    return [
        PromPanel(
            "pg_up",
            "PostgreSQL scrape health (pg_up)",
            lambda _n, svc: f"min(pg_up{{{_pg(svc)},job=~'.*_hr'}})",
            "0-1",
            grade_up,
        ),
        PromPanel(
            "connections",
            "Active backends (sum)",
            lambda _n, svc: f"sum(pg_stat_database_numbackends{{{_pg(svc)},job=~'.*_hr'}})",
            "connections",
            grade_connections,
        ),
        PromPanel(
            "tps",
            "Transaction commits (/s)",
            lambda _n, svc: f"sum(rate(pg_stat_database_xact_commit{{{_pg(svc)},job=~'.*_hr'}}[5m]))",
            "txn/s",
            grade_tps,
        ),
        PromPanel(
            "rollbacks",
            "Transaction rollbacks (/s)",
            lambda _n, svc: f"sum(rate(pg_stat_database_xact_rollback{{{_pg(svc)},job=~'.*_hr'}}[5m]))",
            "txn/s",
            lambda st, sp: (1 if sp else 0, ["rollback rate burst"] if sp else [], []),
        ),
        PromPanel(
            "cache_hit",
            "Buffer cache hit ratio",
            lambda _n, svc: (
                f"sum(rate(pg_stat_database_blks_hit{{{_pg(svc)},job=~'.*_hr'}}[5m])) / "
                f"(sum(rate(pg_stat_database_blks_hit{{{_pg(svc)},job=~'.*_hr'}}[5m])) + "
                f"sum(rate(pg_stat_database_blks_read{{{_pg(svc)},job=~'.*_hr'}}[5m])))"
            ),
            "ratio",
            grade_cache,
        ),
        PromPanel(
            "deadlocks",
            "Deadlocks (/s)",
            lambda _n, svc: f"sum(rate(pg_stat_database_deadlocks{{{_pg(svc)},job=~'.*_hr'}}[5m]))",
            "1/s",
            grade_deadlocks,
        ),
        PromPanel(
            "locks",
            "Locks held (sum)",
            lambda _n, svc: f"sum(pg_locks_count{{{_pg(svc)},job=~'.*_hr'}})",
            "locks",
            grade_locks,
        ),
        PromPanel(
            "temp_bytes",
            "Temp file bytes written (/s)",
            lambda _n, svc: f"sum(rate(pg_stat_database_temp_bytes{{{_pg(svc)},job=~'.*_hr'}}[5m]))",
            "B/s",
            lambda st, sp: (
                (2 if st.max and st.max > 1e6 else 1 if sp else 0),
                ["heavy temp file usage — sort/hash spills likely"] if st.max and st.max > 1e6 else [],
                [],
            ),
        ),
        PromPanel(
            "replication_lag",
            "Replication replay lag (s)",
            lambda _n, svc: (
                f"max(pg_custom_stat_replication_replay_lag_seconds{{{_pg(svc)}}})"
            ),
            "seconds",
            lambda st, sp: (
                (3 if st.max and st.max > 30 else 2 if st.max and st.max > 5 else 0),
                [f"replication replay lag up to {st.max:.1f}s"] if st.max and st.max > 5 else [],
                ["Investigate replica load and network if lag persists."] if st.max and st.max > 30 else [],
            ),
        ),
    ]


def build_pg_maintenance_panels(service: str, step: int) -> list[PromPanel]:
    """Panels from PMM PostgreSQL Instance Summary (wraparound / vacuum)."""
    s = _pg(service)
    win = _prom_range_window(step)

    def grade_wraparound(st: SeriesStats, spikes: list[str]) -> tuple[int, list[str], list[str]]:
        risks, score, imm = [], 0, []
        if st.max and st.max >= 180_000_000:
            risks.append(
                f"wraparound age peaked at {st.max:.0f} — anti-wraparound vacuum zone (>=90% of freeze max)"
            )
            score += 3
            imm.append(
                "Expect elevated read/write IO during anti-wraparound autovacuum; check pg_stat_progress_vacuum."
            )
        elif st.max and st.max >= 160_000_000:
            risks.append(
                f"wraparound age peaked at {st.max:.0f} — approaching autovacuum_freeze_max_age"
            )
            score += 2
        if spikes:
            score = max(score, 1)
        return score, risks, imm

    def grade_dead_tuples(st: SeriesStats, spikes: list[str]) -> tuple[int, list[str], list[str]]:
        risks, score, imm = [], 0, []
        if st.max and st.max > 20:
            risks.append(f"dead tuple ratio peaked at {st.max:.1f}% on at least one large table")
            score += 2
        elif st.max and st.max > 10:
            risks.append(f"dead tuple ratio reached {st.max:.1f}%")
            score += 1
        return score, risks, imm

    return [
        PromPanel(
            "wraparound_age",
            "Transaction wraparound age (max datname)",
            lambda _n, svc: (
                f"topk(5, max by (datname) (pg_database_wraparound_age_datfrozenxid_seconds"
                f"{{{_pg(svc)}, datname!~\"template1|template0\"}}[{win}]))"
            ),
            "xid age",
            grade_wraparound,
        ),
        PromPanel(
            "freeze_max_age",
            "Autovacuum freeze max age (threshold)",
            lambda _n, svc: f"pg_settings_autovacuum_freeze_max_age{{{_pg(svc)}}}",
            "xid",
            lambda st, _sp: (0, [], []),
        ),
        PromPanel(
            "dead_tuples_pct",
            "Dead tuples % (top tables >10k live)",
            lambda _n, svc: (
                f"topk(5,(pg_stat_user_tables_n_dead_tup{{{_pg(svc)}}} * 100) / "
                f"pg_stat_user_tables_n_live_tup{{{_pg(svc)}}} AND "
                f"(pg_stat_user_tables_n_live_tup{{{_pg(svc)}}} > 10000))"
            ),
            "%",
            grade_dead_tuples,
        ),
        PromPanel(
            "tuples_fetched",
            "Tuples fetched (/s) — heap scan pressure",
            lambda _n, svc: (
                f"sum(rate(pg_stat_database_tup_fetched{{{_pg(svc)}}}[5m])) or "
                f"sum(irate(pg_stat_database_tup_fetched{{{_pg(svc)}}}[5m]))"
            ),
            "tuples/s",
            lambda st, sp: (
                (2 if sp and st.max and st.mean and st.max > 5 * st.mean else 1 if sp else 0),
                ["tuple fetch burst — correlate with vacuum or sequential scans"] if sp else [],
                [],
            ),
        ),
    ]


def build_os_panels(node: str, step: int) -> list[PromPanel]:
    """Panels from PMM Node Summary — RDS-aware IO / CPU (Disk IO Latency, Load, Activity)."""
    win = _prom_range_window(step)

    def grade_cpu(st: SeriesStats, spikes: list[str]) -> tuple[int, list[str], list[str]]:
        risks, score, imm = [], 0, []
        if st.max and st.max > 90:
            risks.append(f"CPU peaked at {st.max:.0f}% — immediate capacity review")
            score += 3
            imm.append("Identify top processes; check PG parallel workers and vacuum activity.")
        elif st.max and st.max > 75:
            risks.append(f"CPU peaked at {st.max:.0f}%")
            score += 2
        if spikes:
            score = max(score, 1)
        return score, risks, imm

    def grade_io_latency(st: SeriesStats, spikes: list[str], kind: str) -> tuple[int, list[str], list[str]]:
        risks, score, imm = [], 0, []
        if st.max and st.max >= 0.05:
            risks.append(f"{kind} latency peaked at {st.max * 1000:.1f} ms — storage saturation likely")
            score += 3
            imm.append(
                "Compare with Disk IO Load and wraparound age; latency may lag vacuum due to averaging."
            )
        elif st.max and st.max >= 0.02:
            risks.append(f"{kind} latency peaked at {st.max * 1000:.1f} ms")
            score += 2
        if spikes:
            score = max(score, 1)
        return score, risks, imm

    return [
        PromPanel(
            "node_up",
            "Scrape target up (node / RDS)",
            lambda nd, _s: f'max(up{{{_node(nd)},job=~"rds.*|.*_hr"}})',
            "0-1",
            lambda st, _sp: (
                (3 if st.min is not None and st.min < 1 else 0),
                ["monitoring target down in window"] if st.min is not None and st.min < 1 else [],
                ["Restore pmm-agent / RDS exporter on node."] if st.min is not None and st.min < 1 else [],
            ),
        ),
        PromPanel(
            "cpu_pct",
            "CPU utilization (%) — RDS / node",
            lambda nd, _s: (
                f'avg(avg_over_time(node_cpu_average{{{_node(nd)}, mode=~"user|system|wait|steal|irq|nice"}}[{win}]) '
                f'or avg_over_time(node_cpu_average{{{_node(nd)}, mode=~"user|system|wait|steal|irq|nice"}}[5m]))'
            ),
            "%",
            grade_cpu,
        ),
        PromPanel(
            "disk_read_latency",
            "Disk read latency",
            lambda nd, _s: (
                f"avg by (node_name) ((sum by (node_name) (rate(node_disk_read_time_seconds_total{{{_node(nd)}}}[{win}])) / "
                f"sum by (node_name) (rate(node_disk_reads_completed_total{{{_node(nd)}}}[{win}]) > 0 )) or "
                f"(sum by (node_name) (irate(node_disk_read_time_seconds_total{{{_node(nd)}}}[5m])) / "
                f"sum by (node_name) (irate(node_disk_reads_completed_total{{{_node(nd)}}}[5m]) > 0 )) or "
                f"avg_over_time(aws_rds_read_latency_average{{{_node(nd)}}}[{win}])/1000 or "
                f"avg_over_time(aws_rds_read_latency_average{{{_node(nd)}}}[5m])/1000 or "
                f"avg_over_time(rdsosmetrics_diskIO_readLatency{{{_node(nd)}}}[{win}])/1000 or "
                f"avg_over_time(rdsosmetrics_diskIO_readLatency{{{_node(nd)}}}[5m])/1000)"
            ),
            "s",
            lambda st, sp: grade_io_latency(st, sp, "Read"),
        ),
        PromPanel(
            "disk_write_latency",
            "Disk write latency",
            lambda nd, _s: (
                f"avg by (node_name) ((sum by (node_name) (rate(node_disk_write_time_seconds_total{{{_node(nd)}}}[{win}])) / "
                f"sum by (node_name) (rate(node_disk_writes_completed_total{{{_node(nd)}}}[{win}]) > 0 )) or "
                f"(sum by (node_name) (irate(node_disk_write_time_seconds_total{{{_node(nd)}}}[5m])) / "
                f"sum by (node_name) (irate(node_disk_writes_completed_total{{{_node(nd)}}}[5m]) > 0 )) or "
                f"(avg_over_time(aws_rds_write_latency_average{{{_node(nd)}}}[{win}])/1000 or "
                f"avg_over_time(aws_rds_write_latency_average{{{_node(nd)}}}[5m])/1000) or "
                f"(avg_over_time(rdsosmetrics_diskIO_writeLatency{{{_node(nd)}}}[{win}]) or "
                f"avg_over_time(rdsosmetrics_diskIO_writeLatency{{{_node(nd)}}}[5m]))/1000)"
            ),
            "s",
            lambda st, sp: grade_io_latency(st, sp, "Write"),
        ),
        PromPanel(
            "io_read_throughput",
            "I/O read throughput",
            lambda nd, _s: (
                f"avg by (node_name) (rate(node_vmstat_pgpgin{{{_node(nd)}}}[{win}]) * 1024 or "
                f"irate(node_vmstat_pgpgin{{{_node(nd)}}}[5m]) * 1024 or "
                f"(max_over_time(rdsosmetrics_diskIO_readKbPS{{{_node(nd)}}}[{win}]) or "
                f"max_over_time(rdsosmetrics_diskIO_readKbPS{{{_node(nd)}}}[5m])) * 1024)"
            ),
            "B/s",
            lambda st, sp: ((1 if sp else 0), [], []),
        ),
        PromPanel(
            "io_write_throughput",
            "I/O write throughput",
            lambda nd, _s: (
                f"avg by (node_name) ((rate(node_vmstat_pgpgout{{{_node(nd)}}}[{win}]) * 1024 or "
                f"irate(node_vmstat_pgpgout{{{_node(nd)}}}[5m]) * 1024) or "
                f"(max_over_time(rdsosmetrics_diskIO_writeKbPS{{{_node(nd)}}}[{win}]) or "
                f"max_over_time(rdsosmetrics_diskIO_writeKbPS{{{_node(nd)}}}[5m])) * 1024)"
            ),
            "B/s",
            lambda st, sp: ((1 if sp else 0), [], []),
        ),
        PromPanel(
            "disk_read_load",
            "Disk IO read load (queue depth proxy)",
            lambda nd, _s: (
                f"avg by (node_name) (sum by (node_name) (rate(node_disk_read_time_seconds_total{{{_node(nd)}}}[{win}])) or "
                f"sum by (node_name) (irate(node_disk_read_time_seconds_total{{{_node(nd)}}}[5m])) or "
                f"sum by (node_name) (rdsosmetrics_diskIO_readIOsPS{{{_node(nd)}}}))"
            ),
            "load",
            lambda st, sp: (
                (2 if st.max and st.max > 100 else 1 if sp else 0),
                ["elevated read IO load"] if st.max and st.max > 100 else [],
                [],
            ),
        ),
        PromPanel(
            "disk_write_load",
            "Disk IO write load (queue depth proxy)",
            lambda nd, _s: (
                f"avg by (node_name) (sum by (node_name) (rate(node_disk_write_time_seconds_total{{{_node(nd)}}}[{win}])) or "
                f"sum by (node_name) (irate(node_disk_write_time_seconds_total{{{_node(nd)}}}[5m])) or "
                f"sum by (node_name) (rdsosmetrics_diskIO_writeIOsPS{{{_node(nd)}}}))"
            ),
            "load",
            lambda st, sp: (
                (2 if st.max and st.max > 100 else 1 if sp else 0),
                ["elevated write IO load"] if st.max and st.max > 100 else [],
                [],
            ),
        ),
        PromPanel(
            "load1",
            "Load average (1m)",
            lambda nd, _s: (
                f"avg by (node_name) (avg_over_time(node_load1{{{_node(nd)}}}[{win}]) or "
                f"avg_over_time(node_load1{{{_node(nd)}}}[5m]))"
            ),
            "",
            lambda st, sp: ((2 if st.max and st.max > 8 else 1 if sp else 0), [], []),
        ),
    ]


def analyze_vacuum_io_correlation(
    wraparound_resp: dict[str, Any],
    freeze_resp: dict[str, Any],
    read_lat_resp: dict[str, Any],
    write_lat_resp: dict[str, Any],
    *,
    step: int,
) -> SectionReport:
    """Time-align wraparound age with disk latency (Grafana panel correlation)."""
    wrap = extract_range_series(wraparound_resp)
    freeze_vals = extract_range_values(freeze_resp)
    read_lat = extract_range_series(read_lat_resp)
    write_lat = extract_range_series(write_lat_resp)

    issues: list[str] = []
    immediate: list[str] = []
    score = 0

    if len(wrap) < 2 or (len(read_lat) < 2 and len(write_lat) < 2):
        return SectionReport(
            title="Vacuum / IO correlation",
            grade="C",
            summary="Insufficient series for wraparound vs IO latency correlation.",
            issues=["Need wraparound age and at least one latency series in the window."],
        )

    freeze_max = freeze_vals[-1] if freeze_vals else 200_000_000
    threshold = freeze_max * 0.9

    def index_by_ts(pairs: list[tuple[float, float]]) -> dict[float, float]:
        return {ts: v for ts, v in pairs}

    wrap_by_ts = index_by_ts(wrap)
    read_by_ts = index_by_ts(read_lat)
    write_by_ts = index_by_ts(write_lat)
    common_ts = sorted(set(wrap_by_ts) & (set(read_by_ts) | set(write_by_ts)))
    if len(common_ts) < 2:
        return SectionReport(
            title="Vacuum / IO correlation",
            grade="C",
            summary="No overlapping timestamps between wraparound and latency series.",
            issues=["Prometheus step alignment failed — try a shorter window or smaller step."],
        )

    def latency_spike_threshold(pairs: list[tuple[float, float]]) -> float:
        vals = [v for _, v in pairs]
        if not vals:
            return 0.02
        mean = sum(vals) / len(vals)
        p95 = sorted(vals)[max(0, int(len(vals) * 0.95) - 1)]
        return max(0.01, min(mean * 2, p95 * 1.5))

    read_thr = latency_spike_threshold(read_lat)
    write_thr = latency_spike_threshold(write_lat)

    lat_spikes = 0
    aligned_spikes = 0
    sticky_after_wrap = 0
    lag_steps = max(1, int(3600 / max(step, 1)))

    for ts in common_ts:
        age = wrap_by_ts[ts]
        read_v = read_by_ts.get(ts)
        write_v = write_by_ts.get(ts)
        lat_high = (read_v is not None and read_v >= read_thr) or (
            write_v is not None and write_v >= write_thr
        )
        if not lat_high:
            continue
        lat_spikes += 1
        wrap_elevated = age >= threshold
        if wrap_elevated:
            aligned_spikes += 1
        elif age >= threshold * 0.85:
            aligned_spikes += 1
            issues.append(
                f"Latency spike at {datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()} "
                f"with wraparound age {age:.0f} near threshold {threshold:.0f}"
            )

        if not wrap_elevated:
            for future_ts in common_ts:
                if ts < future_ts <= ts + lag_steps * step:
                    if wrap_by_ts[future_ts] >= threshold * 0.85:
                        continue
                if future_ts > ts and wrap_by_ts.get(future_ts, threshold) < threshold * 0.85:
                    if read_by_ts.get(future_ts, 0) >= read_thr or write_by_ts.get(
                        future_ts, 0
                    ) >= write_thr:
                        sticky_after_wrap += 1
                    break

    wrap_max = max(wrap_by_ts.values())
    read_max = max(read_by_ts.values()) if read_by_ts else None
    write_max = max(write_by_ts.values()) if write_by_ts else None

    summary = (
        f"wraparound max={wrap_max:.0f} (threshold {threshold:.0f}); "
        f"latency spikes={lat_spikes}, aligned with elevated wraparound={aligned_spikes}."
    )
    issues.insert(
        0,
        f"Freeze max age={freeze_max:.0f}; anti-wraparound zone begins ~{threshold:.0f}.",
    )
    if read_max is not None:
        issues.append(f"Peak read latency={read_max * 1000:.2f} ms (spike threshold {read_thr * 1000:.2f} ms).")
    if write_max is not None:
        issues.append(f"Peak write latency={write_max * 1000:.2f} ms (spike threshold {write_thr * 1000:.2f} ms).")

    if lat_spikes == 0:
        grade = "A"
        issues.append("No disk latency spikes detected in the aligned window.")
    elif aligned_spikes / lat_spikes >= 0.5:
        grade = "C"
        score = 2
        issues.append(
            f"{aligned_spikes}/{lat_spikes} latency spikes overlap elevated wraparound age — "
            "anti-wraparound vacuum is a plausible trigger."
        )
        immediate.append("Inspect pg_stat_progress_vacuum and advisor autovacuum checks during spike windows.")
    else:
        grade = "B"
        score = 1
        issues.append(
            f"Only {aligned_spikes}/{lat_spikes} latency spikes align with wraparound pressure — "
            "IO may be driven by workload or averaging artifacts as well."
        )

    if sticky_after_wrap > 0:
        issues.append(
            f"{sticky_after_wrap} latency spike(s) persisted >=1h after wraparound age dropped — "
            "consistent with PMM avg_over_time smoothing or post-vacuum checkpoint IO."
        )
        score = max(score, 1)

    return SectionReport(
        title="Vacuum / IO correlation",
        grade=grade_from_score(score) if score else grade,
        summary=summary,
        issues=issues,
        immediate=immediate,
    )


def collect_prom_section(
    client: PMMClient,
    panels: list[PromPanel],
    node: str,
    service: str,
    start: int,
    end: int,
    step: int,
    out_dir: Path,
    prefix: str,
) -> SectionReport:
    findings: list[MetricFinding] = []
    section_score = 0
    all_issues: list[str] = []
    immediate: list[str] = []

    for panel in panels:
        expr = panel.expr(node, service)
        prom = client.prom_query_range(expr, start, end, step)
        save_json(out_dir, f"prom_{prefix}_{panel.key}.json", {"expr": expr, "response": prom})
        vals = extract_range_values(prom) if prom.get("status") == "success" else []
        stats = analyze_values(vals)
        spikes, spike_score = detect_spikes(stats)
        metric_score, risks, imm = panel.grade_fn(stats, spikes)
        score = max(spike_score, metric_score)
        section_score = max(section_score, score)

        finding = MetricFinding(
            title=panel.title,
            expr=expr,
            stats=stats,
            unit=panel.unit,
            spikes=spikes,
            risks=risks,
        )
        findings.append(finding)
        for s in spikes:
            all_issues.append(f"{panel.title}: {s}")
        for r in risks:
            all_issues.append(f"{panel.title}: {r}")
        immediate.extend(imm)

    grade = grade_from_score(section_score)
    if not any(f.stats.has_data for f in findings):
        grade = "C"
        all_issues.append("Insufficient Prometheus samples — check retention and exporters.")

    return SectionReport(
        title=prefix.replace("_", " ").title(),
        grade=grade,
        summary=f"{len(findings)} metrics evaluated; peak severity score {section_score}.",
        findings=findings,
        issues=all_issues,
        immediate=list(dict.fromkeys(immediate)),
    )


def analyze_qan_report(
    report: Any, main_metric: str
) -> tuple[SectionReport, dict[str, Any]]:
    issues: list[str] = []
    immediate: list[str] = []
    score = 0
    rows = report.get("rows") if isinstance(report, dict) else None
    if not isinstance(rows, list) or not rows:
        return (
            SectionReport(
                title="Query Analytics (QAN)",
                grade="D",
                summary="No QAN rows in window.",
                issues=["QAN returned no query rows — verify pg_stat_statements agent."],
                immediate=["Ensure qan_postgresql_pgstatements_agent is RUNNING."],
            ),
            {},
        )

    def row_load(row: dict[str, Any]) -> float:
        m = row.get("metrics") or {}
        for key in (main_metric, "load", "query_time", "num_queries"):
            cell = m.get(key)
            if isinstance(cell, dict):
                for sk in ("sum_per_sec", "rate", "sum", "avg"):
                    v = cell.get(sk)
                    if isinstance(v, (int, float)):
                        return float(v)
        return 0.0

    ranked = sorted(
        (r for r in rows if isinstance(r, dict) and r.get("dimension")),
        key=row_load,
        reverse=True,
    )
    aggregate = next((r for r in rows if isinstance(r, dict) and not r.get("dimension")), None)

    if len(ranked) >= 2:
        a, b = row_load(ranked[0]), row_load(ranked[1])
        if b > 0 and a / b > 5:
            issues.append(
                f"Dominant queryid {ranked[0].get('dimension')!r}: load ~{a:.4g} vs next ~{b:.4g}"
            )
            score = max(score, 1)

    tail_skew = 0
    for row in ranked[:8]:
        dim = row.get("dimension")
        metrics = row.get("metrics") or {}
        qt = metrics.get("query_time")
        if isinstance(qt, dict):
            avg = qt.get("avg")
            mx = qt.get("max") or qt.get("sum")
            try:
                avgf = float(avg) if avg is not None else None
                mxf = float(mx) if mx is not None else None
            except (TypeError, ValueError):
                avgf = mxf = None
            if avgf and mxf and avgf > 0 and mxf > 20 * avgf:
                issues.append(f"Wide latency spread on queryid={dim!r} (max/avg > 20x)")
                tail_skew += 1
    if tail_skew:
        score = max(score, 1)

    agg_load = row_load(aggregate) if aggregate else 0.0
    summary = f"{len(ranked)} query fingerprints; aggregate load/sec ~{agg_load:.4g}."
    if not issues:
        grade = "A" if ranked else "B"
    else:
        grade = grade_from_score(score)

    return (
        SectionReport(
            title="Query Analytics (QAN)",
            grade=grade,
            summary=summary,
            issues=issues,
            immediate=immediate,
        ),
        {"top_queries": ranked[:10], "aggregate": aggregate},
    )


def analyze_agents(inv_agents: dict[str, Any]) -> SectionReport:
    issues: list[str] = []
    immediate: list[str] = []
    score = 0

    pg_exp: list[str] = []
    qan: dict[str, list[str]] = {k: [] for k in PG_QAN_AGENT_KINDS}
    node_exp: list[str] = []
    if isinstance(inv_agents, dict):
        for agent in inv_agents.get(PG_EXPORTER_KIND) or []:
            if isinstance(agent, dict) and agent.get("status"):
                pg_exp.append(str(agent["status"]))
        for kind in PG_QAN_AGENT_KINDS:
            for agent in inv_agents.get(kind) or []:
                if isinstance(agent, dict) and agent.get("status"):
                    qan[kind].append(str(agent["status"]))
        for agent in inv_agents.get(NODE_EXPORTER_KIND) or []:
            if isinstance(agent, dict) and agent.get("status"):
                node_exp.append(str(agent["status"]))

    def running(statuses: list[str]) -> bool:
        return any(s.endswith("RUNNING") for s in statuses)

    if pg_exp and not running(pg_exp):
        issues.append(f"postgres_exporter not RUNNING: {pg_exp}")
        score = max(score, 3)
        immediate.append("Fix postgres_exporter credentials and target reachability.")
    if not any(qan.values()):
        issues.append("No PostgreSQL QAN agent configured.")
        score = max(score, 2)
    elif not any(running(v) for v in qan.values()):
        issues.append(f"QAN agents not RUNNING: {qan}")
        score = max(score, 2)
    if node_exp and not running(node_exp):
        issues.append(f"node_exporter not RUNNING: {node_exp}")
        score = max(score, 2)

    grade = grade_from_score(score)
    return SectionReport(
        title="Monitoring agents",
        grade=grade,
        summary=f"postgres_exporter={pg_exp or 'n/a'}; QAN={qan}; node_exporter={node_exp or 'n/a'}",
        issues=issues,
        immediate=immediate,
    )


def analyze_advisors(advisors: Any) -> SectionReport:
    issues: list[str] = []
    immediate: list[str] = []
    score = 0
    results = advisors.get("results") if isinstance(advisors, dict) else None
    if not isinstance(results, list) or not results:
        return SectionReport(
            title="Advisors / STT checks",
            grade="A",
            summary="No failed advisor checks for this service.",
        )
    for item in results:
        if not isinstance(item, dict):
            continue
        sev = str(item.get("severity") or "")
        name = item.get("check_name") or item.get("name")
        summary = item.get("summary") or item.get("description") or ""
        if "ERROR" in sev:
            issues.append(f"ERROR {name}: {summary}")
            score = max(score, 3)
            immediate.append(f"Remediate advisor check: {name}")
        elif "WARNING" in sev:
            issues.append(f"WARNING {name}: {summary}")
            score = max(score, 1)
    return SectionReport(
        title="Advisors / STT checks",
        grade=grade_from_score(score),
        summary=f"{len(results)} failed check(s) in window.",
        issues=issues,
        immediate=immediate,
    )


def fmt_stats(st: SeriesStats, unit: str) -> str:
    if not st.has_data:
        return st.note or "no data"
    parts = [
        f"mean={st.mean:.4g}",
        f"max={st.max:.4g}",
        f"last={st.last:.4g}",
    ]
    if st.max_over_mean:
        parts.append(f"max/mean={st.max_over_mean:.2f}x")
    if unit:
        parts.append(unit)
    return ", ".join(parts)


def write_health_report(
    path: Path,
    *,
    service_name: str,
    base_url: str,
    period: dict[str, str],
    out_dir: Path,
    sections: list[SectionReport],
    overall_grade: str,
) -> None:
    lines: list[str] = []
    lines.append("# PMM PostgreSQL health report\n\n")
    lines.append(f"- **Service:** `{service_name}`\n")
    lines.append(f"- **Window (UTC):** `{period['period_start_from']}` → `{period['period_start_to']}`\n")
    lines.append(f"- **PMM:** `{base_url}`\n")
    lines.append(f"- **Overall grade:** **{overall_grade}**\n")
    lines.append(f"- **Artifacts:** `{out_dir}`\n\n")

    imm_all: list[str] = []
    for sec in sections:
        if sec.immediate:
            imm_all.extend(sec.immediate)

    if imm_all:
        lines.append("## Requires immediate attention\n\n")
        for item in dict.fromkeys(imm_all):
            lines.append(f"- {item}\n")
        lines.append("\n")

    lines.append("## Section grades\n\n")
    lines.append("| Section | Grade | Summary |\n")
    lines.append("|---------|-------|--------|\n")
    for sec in sections:
        summary = sec.summary.replace("|", "\\|")[:120]
        lines.append(f"| {sec.title} | **{sec.grade}** | {summary} |\n")
    lines.append("\n")

    for sec in sections:
        lines.append(f"## {sec.title} — grade **{sec.grade}**\n\n")
        lines.append(f"{sec.summary}\n\n")
        if sec.findings:
            lines.append("### Metrics\n\n")
            for f in sec.findings:
                lines.append(f"- **{f.title}:** {fmt_stats(f.stats, f.unit)}\n")
                for sp in f.spikes:
                    lines.append(f"  - Spike: {sp}\n")
                for r in f.risks:
                    lines.append(f"  - Risk: {r}\n")
            lines.append("\n")
        if sec.issues:
            lines.append("### Findings\n\n")
            for issue in sec.issues:
                lines.append(f"- {issue}\n")
            lines.append("\n")

    lines.append("## Methodology\n\n")
    lines.append(
        "- **Data sources:** PMM inventory/QAN/advisor APIs and Prometheus `query_range` via `/prometheus/api/v1`.\n"
    )
    lines.append(
        "- **Spike detection:** max/mean ratio ≥4 (moderate) or ≥10 (sharp); z-score on window max ≥3.\n"
    )
    lines.append(
        "- **Grades:** A (healthy) through F (critical); section grade from worst metric severity in the section.\n"
    )
    lines.append(
        "- **Overall grade:** worst section grade unless all sections are A/B and no immediate items (then capped at B).\n"
    )

    path.write_text("".join(lines), encoding="utf-8")


def collect_and_report(
    client: PMMClient,
    service_query: str,
    base_url: str,
    out_dir: Path,
    t_from: datetime,
    t_to: datetime,
    step: int,
) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    period = {
        "period_start_from": rfc3339(t_from),
        "period_start_to": rfc3339(t_to),
    }

    svc, note = find_pg_service(client, service_query)
    save_json(out_dir, "inventory_service.json", {"match": note, "service": svc})
    sid = str(svc.get("service_id") or "")
    sname = str(svc.get("service_name") or service_query)
    node_id = str(svc.get("node_id") or "")
    node_name = resolve_node_name(client, node_id) if node_id else sname
    save_json(
        out_dir,
        "_run_meta.json",
        {
            "base_url": base_url,
            "service_query": service_query,
            "node_name": node_name,
            "node_id": node_id,
            **period,
            "step_seconds": step,
        },
    )

    st, detail = client.request("GET", f"/v1/inventory/services/{sid}")
    save_json(out_dir, "inventory_service_detail.json", {"http_status": st, "body": detail})

    st, inv_agents = client.request("GET", "/v1/inventory/agents", query={"service_id": sid})
    save_json(out_dir, "inventory_agents.json", {"http_status": st, "body": inv_agents})

    st, node_agents = client.request("GET", "/v1/inventory/agents", query={"node_id": node_id})
    save_json(out_dir, "inventory_node_agents.json", {"http_status": st, "body": node_agents})

    merged_agents: dict[str, Any] = {}
    for blob in (inv_agents, node_agents):
        if isinstance(blob, dict):
            for k, v in blob.items():
                if isinstance(v, list):
                    merged_agents.setdefault(k, [])
                    merged_agents[k].extend(v)

    agents_section = analyze_agents(merged_agents)

    st, advisors = client.request(
        "GET", "/v1/advisors/checks/failed", query={"service_id": sid}
    )
    save_json(out_dir, "advisors_failed.json", {"http_status": st, "body": advisors})
    advisors_section = analyze_advisors(advisors if isinstance(advisors, dict) else {})

    st, qhealth = client.request("GET", "/v1/qan/health")
    save_json(out_dir, "qan_health.json", {"http_status": st, "body": qhealth})

    st, metric_names = client.request("POST", "/v1/qan/metrics:getNames", json_body={})
    save_json(out_dir, "qan_metric_names.json", {"http_status": st, "body": metric_names})

    main_metric = "load"
    if isinstance(metric_names, dict) and isinstance(metric_names.get("data"), dict):
        names = metric_names["data"]
        for pref in ("load", "query_time", "num_queries", "m_query_time_sum"):
            if pref in names:
                main_metric = pref
                break

    labels = [{"key": "service_name", "value": [sname]}]
    report_body: dict[str, Any] = {
        **period,
        "group_by": "queryid",
        "labels": labels,
        "main_metric": main_metric,
        "limit": 25,
        "columns": [main_metric, "query_time", "num_queries"],
    }
    st, report = client.request("POST", "/v1/qan/metrics:getReport", json_body=report_body)
    if st != 200:
        report_body.pop("order_by", None)
        st, report = client.request("POST", "/v1/qan/metrics:getReport", json_body=report_body)
    save_json(out_dir, "qan_report.json", {"http_status": st, "main_metric": main_metric, "body": report})

    qan_section, _ = analyze_qan_report(report, main_metric)

    start_ts = int(t_from.timestamp())
    end_ts = int(t_to.timestamp())

    db_section = collect_prom_section(
        client,
        build_pg_panels(sname),
        node_name,
        sname,
        start_ts,
        end_ts,
        step,
        out_dir,
        "postgresql",
    )
    maintenance_section = collect_prom_section(
        client,
        build_pg_maintenance_panels(sname, step),
        node_name,
        sname,
        start_ts,
        end_ts,
        step,
        out_dir,
        "pg_maintenance",
    )
    os_section = collect_prom_section(
        client,
        build_os_panels(node_name, step),
        node_name,
        sname,
        start_ts,
        end_ts,
        step,
        out_dir,
        "os",
    )

    def load_prom_artifact(name: str) -> dict[str, Any]:
        path = out_dir / name
        if not path.is_file():
            return {}
        data = json.loads(path.read_text(encoding="utf-8"))
        return data.get("response") if isinstance(data, dict) else {}

    correlation_section = analyze_vacuum_io_correlation(
        load_prom_artifact("prom_pg_maintenance_wraparound_age.json"),
        load_prom_artifact("prom_pg_maintenance_freeze_max_age.json"),
        load_prom_artifact("prom_os_disk_read_latency.json"),
        load_prom_artifact("prom_os_disk_write_latency.json"),
        step=step,
    )
    save_json(out_dir, "vacuum_io_correlation.json", {"summary": correlation_section.summary, "issues": correlation_section.issues})

    sections = [
        agents_section,
        advisors_section,
        db_section,
        maintenance_section,
        os_section,
        correlation_section,
        qan_section,
    ]
    overall = worst_grade(*(s.grade for s in sections))
    if overall in ("A", "B") and any(s.immediate for s in sections):
        overall = "C"

    report_path = out_dir / "HEALTH_REPORT.md"
    write_health_report(
        report_path,
        service_name=sname,
        base_url=base_url,
        period=period,
        out_dir=out_dir,
        sections=sections,
        overall_grade=overall,
    )
    return report_path


def run() -> int:
    ap = argparse.ArgumentParser(
        description="PMM v3 PostgreSQL health scraper and graded report (default: last 6h)"
    )
    ap.add_argument(
        "service",
        nargs="?",
        default="sep-test-pg1-postgresql",
        help="PostgreSQL service_name or service_id",
    )
    ap.add_argument(
        "--base-url",
        default=os.environ.get("PMM_BASE_URL", "https://127.0.0.1:18003"),
    )
    ap.add_argument(
        "--cred-file",
        type=Path,
        default=Path(os.environ.get("CRED_FILE", "cred")),
    )
    ap.add_argument(
        "--hours",
        type=float,
        default=float(os.environ.get("PMM_HOURS", "6")),
        help="Lookback window in hours (default: 6)",
    )
    ap.add_argument(
        "--step",
        type=int,
        default=int(os.environ.get("PMM_STEP", "300")),
        help="Prometheus range step in seconds (default: 300)",
    )
    ap.add_argument(
        "--artifacts",
        type=Path,
        default=Path("artifacts"),
        help="Artifacts root; report goes under artifacts/pmm-<service>/<timestamp>/",
    )
    args = ap.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    cred_path = args.cred_file if args.cred_file.is_absolute() else repo_root / args.cred_file
    if not cred_path.is_file():
        raise SystemExit(f"Missing cred file: {cred_path}")
    user, password = load_cred(cred_path)

    t_to = utc_now()
    t_from = t_to - timedelta(hours=args.hours)
    run_ts = t_to.strftime("%Y%m%dT%H%M%SZ")
    artifacts_root = args.artifacts if args.artifacts.is_absolute() else repo_root / args.artifacts
    out_dir = artifacts_root / f"pmm-{args.service}" / run_ts

    client = PMMClient(args.base_url, user, password)
    report_path = collect_and_report(
        client,
        args.service,
        args.base_url,
        out_dir,
        t_from,
        t_to,
        args.step,
    )
    print(report_path.read_text(encoding="utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
