#!/usr/bin/env python3
"""Fetch PMM Prometheus overview metrics for Top Query reports (CPU, tuples, DML)."""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pmm_pg_health_report import PMMClient, load_cred  # noqa: E402


def parse_rfc3339(s: str) -> datetime:
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s)


def series_stats(values: list[float]) -> dict[str, float] | None:
    if not values:
        return None
    mean = sum(values) / len(values)
    mx = max(values)
    return {
        "min": min(values),
        "max": mx,
        "mean": mean,
        "last": values[-1],
        "max_over_mean": mx / mean if mean > 1e-12 else 0.0,
        "points": len(values),
    }


def extract_values(resp: dict) -> list[float]:
    out: list[float] = []
    for s in resp.get("data", {}).get("result", []):
        for _, v in s.get("values", []):
            try:
                out.append(float(v))
            except (TypeError, ValueError):
                pass
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Fetch PMM overview Prometheus metrics")
    ap.add_argument("--base-url", default="https://127.0.0.1:18001")
    ap.add_argument("--cred-file", type=Path, default=Path("cred"))
    ap.add_argument("--service", default="sepgsql1-postgresql")
    ap.add_argument("--node-name", default="sepgsql1")
    ap.add_argument("--from", dest="t_from", required=True)
    ap.add_argument("--to", dest="t_to", required=True)
    ap.add_argument("--step", type=int, default=300)
    ap.add_argument("--out-dir", type=Path, required=True)
    args = ap.parse_args()

    repo = Path(__file__).resolve().parents[1]
    cred = args.cred_file if args.cred_file.is_absolute() else repo / args.cred_file
    user, password = load_cred(cred)
    client = PMMClient(args.base_url, user, password)

    t_from = parse_rfc3339(args.t_from)
    t_to = parse_rfc3339(args.t_to)
    start = int(t_from.timestamp())
    end = int(t_to.timestamp())
    pg = f'service_name="{args.service}",job=~".*_hr"'
    nd = f'node_name="{args.node_name}"'

    queries = {
        "prom_os_cpu_pct.json": (
            f'100 - (avg(rate(node_cpu_seconds_total{{{nd},mode="idle"}}[5m])) * 100)'
        ),
        "prom_os_cpu_pct_rds.json": (
            f'avg(avg_over_time(rdsosmetrics_cpuUtilization_total{{{nd}}}[5m]))'
        ),
        "prom_os_load1.json": f'node_load1{{{nd}}}',
        "prom_postgresql_connections.json": f"sum(pg_stat_database_numbackends{{{pg}}})",
        "prom_postgresql_tup_returned.json": f"sum(rate(pg_stat_database_tup_returned{{{pg}}}[5m]))",
        "prom_postgresql_tup_fetched.json": f"sum(rate(pg_stat_database_tup_fetched{{{pg}}}[5m]))",
        "prom_postgresql_tup_inserted.json": f"sum(rate(pg_stat_database_tup_inserted{{{pg}}}[5m]))",
        "prom_postgresql_tup_updated.json": f"sum(rate(pg_stat_database_tup_updated{{{pg}}}[5m]))",
        "prom_postgresql_tup_deleted.json": f"sum(rate(pg_stat_database_tup_deleted{{{pg}}}[5m]))",
    }

    args.out_dir.mkdir(parents=True, exist_ok=True)
    overview: dict[str, dict] = {}
    for filename, expr in queries.items():
        resp = client.prom_query_range(expr, start, end, args.step)
        payload = {"expr": expr, "response": resp}
        (args.out_dir / filename).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        key = filename.replace("prom_", "").replace(".json", "")
        st = series_stats(extract_values(resp))
        overview[key] = {"expr": expr, "stats": st}

    (args.out_dir / "pmm_metrics_overview.json").write_text(
        json.dumps(overview, indent=2), encoding="utf-8"
    )
    print(json.dumps(overview, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
