#!/usr/bin/env python3
"""
Collect PMM v2 API data for one or more PostgreSQL services over an explicit
UTC time window and emit a heuristic REPORT.md per service.

Targets PMM v2 (e.g. 2.44.x) — the gRPC-gateway style endpoints differ from the
v3 ones used by pmm_service_hour_audit.py. Auth: HTTP Basic from cred file.
"""
from __future__ import annotations

import argparse
import base64
import json
import math
import os
import re
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlencode, urlparse


PG_QAN_AGENT_KINDS = (
    "qan_postgresql_pgstatements_agent",
    "qan_postgresql_pgstatmonitor_agent",
)
PG_EXPORTER_KIND = "postgres_exporter"


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


_RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})$"
)


def parse_rfc3339(value: str, flag: str) -> datetime:
    s = value.strip()
    if not _RFC3339_RE.match(s):
        raise SystemExit(
            f"{flag} must be RFC3339, e.g. 2026-04-14T14:02:10Z (got: {value!r})"
        )
    iso = s.replace("Z", "+00:00") if s.endswith("Z") else s
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError as exc:
        raise SystemExit(f"{flag} is not a valid datetime: {exc}") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


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
            with urllib.request.urlopen(req, context=self._ctx, timeout=120) as resp:
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


def save_json(out_dir: Path, name: str, payload: Any) -> None:
    p = out_dir / name
    p.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")


def find_pg_service(
    client: PMMClient, target: str
) -> tuple[dict[str, Any], str]:
    """PMM v2: POST /v1/inventory/Services/List then filter client-side."""
    status, data = client.request(
        "POST",
        "/v1/inventory/Services/List",
        json_body={"service_type": "POSTGRESQL_SERVICE"},
    )
    if status != 200 or not isinstance(data, dict):
        raise SystemExit(f"Services/List failed: HTTP {status} {data!r}")
    pg = data.get("postgresql") or []
    if not isinstance(pg, list):
        pg = []
    for svc in pg:
        if not isinstance(svc, dict):
            continue
        if svc.get("service_name") == target:
            return svc, "matched service_name in inventory list"
        if svc.get("service_id") == target:
            return svc, "matched service_id in inventory list"
    st2, one = client.request(
        "POST", "/v1/inventory/Services/Get", json_body={"service_id": target}
    )
    if st2 == 200 and isinstance(one, dict) and one.get("postgresql"):
        m = one["postgresql"]
        if isinstance(m, dict):
            return m, "Services/Get returned postgresql by service_id"
    raise SystemExit(
        f"Service {target!r} not found among {len(pg)} PostgreSQL inventory services."
    )


def labels_for(service_name: str, service_id: str, label_key: str) -> list[dict[str, Any]]:
    val = service_name if label_key == "service_name" else service_id
    return [{"key": label_key, "value": [val]}]


def period_body(t_from: datetime, t_to: datetime) -> dict[str, Any]:
    return {"period_start_from": rfc3339(t_from), "period_start_to": rfc3339(t_to)}


_SPARKLINE_META_KEYS = {"point", "timestamp", "time_frame"}


def sparkline_loads(sparkline: list[Any]) -> list[float]:
    """Extract per-bucket metric values from a PMM v2 sparkline point list.

    PMM v2 returns bucket metadata (`point` = bucket index, `timestamp`,
    `time_frame`) on every entry and adds metric fields (e.g. `load`,
    `m_*_per_sec`) only on buckets that contain real data. We pick the first
    metric-looking key per bucket; if a point only carries metadata, treat it
    as a gap (no datum) so that "no QAN data" doesn't masquerade as a series.
    """
    out: list[float] = []
    for pt in sparkline or []:
        if not isinstance(pt, dict):
            continue
        v: Optional[float] = None
        for k, raw in pt.items():
            if k in _SPARKLINE_META_KEYS:
                continue
            if isinstance(raw, (int, float)):
                f = float(raw)
                if not math.isnan(f):
                    v = f
                    break
        if v is None:
            v_load = pt.get("load")
            if isinstance(v_load, (int, float)) and not math.isnan(float(v_load)):
                v = float(v_load)
        if v is not None:
            out.append(v)
    return out


def sparkline_stats(sparkline: list[Any]) -> dict[str, Any]:
    loads = sparkline_loads(sparkline)
    if len(loads) < 2:
        return {"n": len(loads), "note": "insufficient points"}
    mean = sum(loads) / len(loads)
    var = sum((x - mean) ** 2 for x in loads) / max(len(loads) - 1, 1)
    stdev = math.sqrt(var)
    mx = max(loads)
    ratio = mx / mean if mean > 1e-12 else None
    cv = stdev / mean if mean > 1e-12 else None
    return {
        "n": len(loads),
        "mean_load": mean,
        "stdev_load": stdev,
        "max_load": mx,
        "max_over_mean": ratio,
        "coef_variation": cv,
    }


def worst_sparkline_from_metrics_response(resp: Any) -> tuple[dict[str, Any], Optional[str]]:
    """Use top-level sparkline if present (service aggregate); else best per-row."""
    if isinstance(resp, dict):
        top = resp.get("sparkline")
        if isinstance(top, list) and len(top) >= 2:
            return sparkline_stats(top), "(service_aggregate)"
    best_cv = -1.0
    best_stats: dict[str, Any] = {"n": 0, "note": "no sparkline"}
    best_dim: Optional[str] = None
    rows = resp.get("rows") if isinstance(resp, dict) else None
    if not isinstance(rows, list):
        return best_stats, None
    for row in rows:
        if not isinstance(row, dict):
            continue
        sl = row.get("sparkline")
        if not isinstance(sl, list):
            continue
        st = sparkline_stats(sl)
        cv = st.get("coef_variation")
        if isinstance(cv, float) and not math.isnan(cv) and cv > best_cv:
            best_cv = cv
            best_stats = st
            best_dim = str(row.get("dimension") or row.get("fingerprint") or "")
    return best_stats, best_dim


def analyze_report_rows(rows: list[Any], main_metric: str) -> list[str]:
    issues: list[str] = []
    if not rows:
        issues.append("QAN GetReport returned no rows for this window/filters.")
        return issues

    def row_sum(row: dict[str, Any]) -> float:
        m = row.get("metrics") or {}
        if not isinstance(m, dict):
            return 0.0
        for key in (main_metric, "query_time", "load", "count"):
            cell = m.get(key)
            if isinstance(cell, dict):
                st = cell.get("stats") or {}
                if isinstance(st, dict):
                    for sk in ("sum", "rate", "avg"):
                        v = st.get(sk)
                        if isinstance(v, (int, float)) and not math.isnan(float(v)):
                            return float(v)
        return 0.0

    ranked = sorted(
        (r for r in rows if isinstance(r, dict)),
        key=row_sum,
        reverse=True,
    )
    if len(ranked) >= 2:
        s0, s1 = row_sum(ranked[0]), row_sum(ranked[1])
        if s1 > 0 and s0 / s1 > 5:
            issues.append(
                f"Dominant query fingerprint: top dimension={ranked[0].get('dimension')!r} "
                f"sum~{s0:.4g} vs second sum~{s1:.4g} (>{5}x)."
            )
    for row in ranked[:10]:
        dim = row.get("dimension") if isinstance(row, dict) else None
        metrics = (row.get("metrics") or {}) if isinstance(row, dict) else {}
        if not isinstance(metrics, dict):
            continue
        for mname, cell in metrics.items():
            if "time" not in mname and mname not in ("load",):
                continue
            if not isinstance(cell, dict):
                continue
            st = cell.get("stats") or {}
            if not isinstance(st, dict):
                continue
            p99 = st.get("p99")
            avg = st.get("avg")
            try:
                p99f = float(p99) if p99 is not None else None
                avgf = float(avg) if avg is not None else None
            except (TypeError, ValueError):
                continue
            if p99f and avgf and avgf > 0 and not math.isnan(p99f) and not math.isnan(avgf):
                if p99f > 8 * avgf:
                    issues.append(
                        f"Tail skew on {mname} for queryid={dim!r}: p99={p99f:.4g} vs avg={avgf:.4g} (~{p99f/avgf:.1f}x)."
                    )
    return issues


def filter_advisor_results_for_service(
    advisor_results: list[Any], service_id: str, service_name: str
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for item in advisor_results or []:
        if not isinstance(item, dict):
            continue
        if item.get("service_id") == service_id or item.get("service_name") == service_name:
            out.append(item)
    return out


def audit_service(
    client: PMMClient,
    service: str,
    base_url: str,
    artifacts_root: Path,
    run_ts: str,
    period: dict[str, Any],
    advisor_cache: dict[str, Any],
) -> Path:
    """Collect everything for one PG service and write artifacts + REPORT.md."""
    out_dir = artifacts_root / f"pmm-{service}" / run_ts
    out_dir.mkdir(parents=True, exist_ok=True)

    meta: dict[str, Any] = {
        "base_url": base_url,
        "service_query": service,
        "period_start_from": period["period_start_from"],
        "period_start_to": period["period_start_to"],
        "artifacts_dir": str(out_dir),
        "engine": "postgresql",
        "pmm_api_flavor": "v2",
    }
    save_json(out_dir, "_run_meta.json", meta)

    svc, note = find_pg_service(client, service)
    save_json(out_dir, "inventory_service_match.json", {"match_note": note, "service": svc})
    sid = svc.get("service_id")
    sname = svc.get("service_name")
    if not sid:
        raise SystemExit("Resolved service has no service_id")

    st, detail = client.request(
        "POST", "/v1/inventory/Services/Get", json_body={"service_id": sid}
    )
    save_json(out_dir, "inventory_service_detail.json", {"http_status": st, "body": detail})

    st, inv_agents = client.request(
        "POST", "/v1/inventory/Agents/List", json_body={"service_id": sid}
    )
    save_json(out_dir, "inventory_agents.json", {"http_status": st, "body": inv_agents})

    pg_qan_statuses: dict[str, list[str]] = {k: [] for k in PG_QAN_AGENT_KINDS}
    pg_exporter_statuses: list[str] = []
    if isinstance(inv_agents, dict):
        for kind in PG_QAN_AGENT_KINDS:
            for agent in inv_agents.get(kind) or []:
                if isinstance(agent, dict) and agent.get("status"):
                    pg_qan_statuses[kind].append(str(agent["status"]))
        for agent in inv_agents.get(PG_EXPORTER_KIND) or []:
            if isinstance(agent, dict) and agent.get("status"):
                pg_exporter_statuses.append(str(agent["status"]))

    st, mgmt_agents = client.request(
        "POST", "/v1/management/Agent/List", json_body={"service_id": sid}
    )
    save_json(out_dir, "management_agents.json", {"http_status": st, "body": mgmt_agents})

    if "results" not in advisor_cache:
        st_adv, adv_resp = client.request(
            "POST", "/v1/management/SecurityChecks/FailedChecks", json_body={}
        )
        advisor_cache["http_status"] = st_adv
        advisor_cache["body"] = adv_resp
        advisor_cache["results"] = (
            adv_resp.get("results") if isinstance(adv_resp, dict) else None
        ) or []
    service_advisors = filter_advisor_results_for_service(
        advisor_cache.get("results") or [], str(sid), str(sname)
    )
    save_json(
        out_dir,
        "advisors_checks_failed.json",
        {
            "http_status": advisor_cache.get("http_status"),
            "filtered_for_service_id": sid,
            "filtered_for_service_name": sname,
            "total_results_across_all_services": len(advisor_cache.get("results") or []),
            "results": service_advisors,
        },
    )

    st, qhealth = client.request("GET", "/v0/qan/Status/Health")
    if st == 404:
        st, qhealth = client.request("GET", "/v1/qan/health")
    save_json(out_dir, "qan_health.json", {"http_status": st, "body": qhealth})

    st, metric_names = client.request("POST", "/v0/qan/GetMetricsNames", json_body={})
    save_json(out_dir, "qan_metrics_getNames.json", {"http_status": st, "body": metric_names})

    label_key = "service_name"
    label_val = sname or service
    qan_labels = labels_for(str(label_val), str(sid), label_key)

    def qan_post(path: str, extra: dict[str, Any]) -> tuple[int, Any]:
        body = {**period, **extra}
        return client.request("POST", path, json_body=body)

    st, filters = qan_post(
        "/v0/qan/Filters/Get",
        {"labels": qan_labels},
    )
    save_json(
        out_dir,
        "qan_metrics_getFilters.json",
        {"http_status": st, "body": filters, "labels_attempt": label_key},
    )

    if st != 200 or not (isinstance(filters, dict) and filters.get("labels")):
        label_key = "service_id"
        qan_labels = labels_for(str(label_val), str(sid), label_key)
        st, filters = qan_post("/v0/qan/Filters/Get", {"labels": qan_labels})
        save_json(
            out_dir,
            "qan_metrics_getFilters_retry_service_id.json",
            {"http_status": st, "body": filters, "labels_attempt": label_key},
        )

    main_metric = "load"
    if isinstance(metric_names, dict) and isinstance(metric_names.get("data"), dict):
        names = metric_names["data"]
        for pref in ("load", "query_time", "count"):
            if pref in names:
                main_metric = pref
                break

    st, metrics = qan_post(
        "/v0/qan/ObjectDetails/GetMetrics",
        {
            "labels": qan_labels,
            "filter_by": "",
            "group_by": "queryid",
            "totals": True,
            "include_only_fields": [main_metric],
        },
    )
    save_json(
        out_dir,
        "qan_getMetrics_totals.json",
        {"http_status": st, "body": metrics, "main_metric": main_metric, "labels": label_key},
    )

    st, metrics_ts = qan_post(
        "/v0/qan/ObjectDetails/GetMetrics",
        {
            "labels": qan_labels,
            "filter_by": "",
            "group_by": "queryid",
            "totals": False,
            "include_only_fields": [main_metric],
        },
    )
    save_json(
        out_dir,
        "qan_getMetrics_timeseries.json",
        {"http_status": st, "body": metrics_ts, "main_metric": main_metric},
    )

    data_names = (
        metric_names.get("data") if isinstance(metric_names, dict) else None
    ) or {}

    def pick_metric_col(*candidates: str) -> Optional[str]:
        for c in candidates:
            if c in data_names:
                return c
        return None

    report_columns = [main_metric]
    for extra in (
        pick_metric_col("query_time"),
        pick_metric_col("count", "num_queries"),
        pick_metric_col("rows_sent"),
        pick_metric_col("m_blk_read_time", "blk_read_time"),
        pick_metric_col("m_blk_write_time", "blk_write_time"),
    ):
        if extra and extra not in report_columns:
            report_columns.append(extra)

    report_body: dict[str, Any] = {
        **period,
        "group_by": "queryid",
        "labels": qan_labels,
        "main_metric_name": main_metric,
        "limit": 25,
        "columns": report_columns,
        "order_by": f"-{main_metric}",
    }
    report_st, report = client.request("POST", "/v0/qan/GetReport", json_body=report_body)
    if report_st != 200:
        rb2 = {k: v for k, v in report_body.items() if k != "order_by"}
        report_st, report = client.request("POST", "/v0/qan/GetReport", json_body=rb2)
    save_json(
        out_dir,
        "qan_metrics_getReport.json",
        {"http_status": report_st, "body": report},
    )

    top_ids: list[str] = []
    if isinstance(report, dict):
        rows = report.get("rows") or []
        if isinstance(rows, list):
            for row in rows[:3]:
                if isinstance(row, dict):
                    d = row.get("dimension")
                    if isinstance(d, str) and d.strip():
                        top_ids.append(d)
    for i, qid in enumerate(top_ids):
        hist_st, hist = qan_post(
            "/v0/qan/ObjectDetails/GetHistogram",
            {"labels": qan_labels, "filter_by": qid, "group_by": "queryid"},
        )
        save_json(
            out_dir,
            f"qan_getHistogram_{i}.json",
            {"http_status": hist_st, "body": hist, "queryid": qid},
        )

    lines: list[str] = []
    lines.append("# PMM PostgreSQL audit\n")
    lines.append(f"- **Window (UTC):** `{period['period_start_from']}` -> `{period['period_start_to']}`\n")
    lines.append(f"- **Base URL:** `{base_url}`\n")
    lines.append(f"- **Target:** `{service}`\n")
    lines.append(f"- **Resolution:** {note}\n")
    lines.append(
        f"- **Inventory:** `service_id={sid}`, `service_name={sname!r}`, `node_id={svc.get('node_id')!r}`\n"
    )
    lines.append(f"- **QAN label filter used:** `{label_key}`\n")
    lines.append(f"- **Artifacts:** `{out_dir}`\n")

    lines.append("\n## API calls recorded\n")
    for fn in sorted(p.name for p in out_dir.glob("*.json") if p.name != "_run_meta.json"):
        lines.append(f"- `{fn}`\n")

    lines.append("\n## Inventory snapshot\n")
    lines.append(
        f"- Address: `{svc.get('address')}` port `{svc.get('port')}` "
        f"database `{svc.get('database_name')}` cluster `{svc.get('cluster')}` "
        f"env `{svc.get('environment')}`\n"
    )

    lines.append("\n## Agents snapshot\n")
    lines.append(f"- `postgres_exporter` statuses: `{pg_exporter_statuses or 'none configured'}`\n")
    for kind in PG_QAN_AGENT_KINDS:
        lines.append(f"- `{kind}` statuses: `{pg_qan_statuses[kind] or 'none configured'}`\n")

    lines.append("\n## Findings and oddities\n")
    issues: list[str] = []

    qan_agent_any_running = any(
        str(s).upper().endswith("RUNNING")
        for statuses in pg_qan_statuses.values()
        for s in statuses
    )
    qan_agent_any_configured = any(pg_qan_statuses.values())
    if qan_agent_any_configured and not qan_agent_any_running:
        issues.append(
            "No PG QAN agent (pg_stat_statements or pg_stat_monitor) reports RUNNING - "
            "expect weak or empty QAN data until at least one is healthy."
        )
    elif not qan_agent_any_configured:
        issues.append(
            "No PG QAN agent is configured for this service - QAN query-level metrics will be empty."
        )
    if pg_exporter_statuses and not any(
        str(s).upper().endswith("RUNNING") for s in pg_exporter_statuses
    ):
        issues.append(
            f"postgres_exporter not RUNNING for this service: {pg_exporter_statuses} - "
            "node/database metrics may be stale."
        )

    if report_st != 200:
        issues.append(f"GetReport HTTP {report_st}: {str(report)[:500]}")

    rows_for_analysis = report.get("rows") if isinstance(report, dict) else None
    if isinstance(rows_for_analysis, list) and len(rows_for_analysis) == 1:
        r0 = rows_for_analysis[0]
        if isinstance(r0, dict) and not (r0.get("dimension") or "").strip():
            m0 = r0.get("metrics") or {}
            st0 = (
                (m0.get(main_metric) or {}).get("stats")
                if isinstance(m0.get(main_metric), dict)
                else None
            )
            if isinstance(st0, dict) and (st0.get("cnt") in (0, None)) and not st0:
                issues.append(
                    "QAN GetReport returned a single empty 'service_aggregate' row - "
                    "typical when no PG QAN agent is running or no queries qualified in the window."
                )

    sev_counts: dict[str, int] = {}
    for item in service_advisors:
        sev = str(item.get("severity") or "UNKNOWN")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
    lines.append(
        f"- Advisor checks (filtered to this service): **{len(service_advisors)}** items; severity counts: `{sev_counts or '{}'}`\n"
    )
    warn_cap = 0
    for item in service_advisors:
        if item.get("severity") == "SEVERITY_ERROR":
            issues.append(
                f"Advisor ERROR `{item.get('check_name')}`: {item.get('summary')}"
            )
        elif item.get("severity") == "SEVERITY_WARNING" and warn_cap < 5:
            issues.append(
                f"Advisor WARNING `{item.get('check_name')}`: {item.get('summary')}"
            )
            warn_cap += 1

    if isinstance(qhealth, dict) and qhealth.get("message"):
        issues.append(f"QAN health message: {qhealth.get('message')}")

    sls, sl_dim = worst_sparkline_from_metrics_response(metrics_ts)
    if sls.get("n") == 0 and isinstance(metrics, dict):
        sls, sl_dim = worst_sparkline_from_metrics_response(metrics)
    lines.append(
        f"- **Worst per-query sparkline (by load CV):** dimension `{sl_dim}` stats `{sls}`\n"
    )
    if isinstance(sls.get("max_over_mean"), float) and sls["max_over_mean"] and sls["max_over_mean"] > 4:
        issues.append(
            f"Bursty load in-window (dim {sl_dim!r}): sparkline max/mean ratio {sls['max_over_mean']:.2f} (threshold 4)."
        )
    if isinstance(sls.get("coef_variation"), float) and sls["coef_variation"] and sls["coef_variation"] > 1.2:
        issues.append(
            f"High relative volatility (dim {sl_dim!r}): sparkline CV {sls['coef_variation']:.2f} (threshold 1.2)."
        )
    if sls.get("n") == 0:
        issues.append(
            "No sparkline points parsed from qan_getMetrics_timeseries.json - check label filter or QAN data lag."
        )

    if isinstance(rows_for_analysis, list):
        issues.extend(analyze_report_rows(rows_for_analysis, main_metric))

    if not issues:
        lines.append("- No strong heuristic flags in this pass (or insufficient series).\n")
    else:
        for it in issues:
            lines.append(f"- {it}\n")

    lines.append("\n## Suggested actions (map to findings above)\n")
    lines.append(
        "- **Dominant / skewed query:** capture `queryid`, run `EXPLAIN (ANALYZE, BUFFERS)`, review indexes and join order.\n"
    )
    lines.append(
        "- **Burst load:** correlate with deploys/cron/replication catch-up; consider rate limits, statement timeouts, connection pooling (pgbouncer).\n"
    )
    lines.append(
        "- **Empty QAN / sparkline:** confirm `pmm-agent` and one of `qan_postgresql_pgstatements_agent` / `qan_postgresql_pgstatmonitor_agent` are RUNNING; verify the underlying extension is loaded in the target database.\n"
    )
    lines.append(
        "- **Advisor failures:** follow each check remediation text in `advisors_checks_failed.json` (version, security, config).\n"
    )

    report_path = out_dir / "REPORT.md"
    report_path.write_text("".join(lines), encoding="utf-8")
    return out_dir


def run() -> int:
    ap = argparse.ArgumentParser(
        description="PMM v2 PostgreSQL service audit over an explicit UTC window"
    )
    ap.add_argument(
        "services",
        nargs="+",
        help="One or more PostgreSQL service_name (or service_id) values",
    )
    ap.add_argument(
        "--base-url",
        default=os.environ.get("PMM_BASE_URL", "https://127.0.0.1:18001"),
    )
    ap.add_argument(
        "--cred-file",
        type=Path,
        default=Path(os.environ.get("CRED_FILE", "cred")),
    )
    ap.add_argument(
        "--artifacts",
        type=Path,
        default=Path("artifacts"),
        help="Artifacts root directory (per-service subfolder created inside)",
    )
    ap.add_argument("--from", dest="t_from", required=True, help="RFC3339 UTC start, e.g. 2026-04-14T14:02:10Z")
    ap.add_argument("--to", dest="t_to", required=True, help="RFC3339 UTC end, e.g. 2026-04-14T19:52:15Z")
    args = ap.parse_args()

    t_from = parse_rfc3339(args.t_from, "--from")
    t_to = parse_rfc3339(args.t_to, "--to")
    if t_to <= t_from:
        raise SystemExit("--to must be strictly greater than --from")

    repo_root = Path(__file__).resolve().parents[1]
    cred_path = args.cred_file if args.cred_file.is_absolute() else repo_root / args.cred_file
    if not cred_path.is_file():
        raise SystemExit(f"Missing cred file: {cred_path}")
    user, password = load_cred(cred_path)

    artifacts_root = args.artifacts if args.artifacts.is_absolute() else repo_root / args.artifacts
    artifacts_root.mkdir(parents=True, exist_ok=True)

    run_ts = utc_now().strftime("%Y%m%dT%H%M%SZ")
    period = period_body(t_from, t_to)

    client = PMMClient(args.base_url, user, password)
    advisor_cache: dict[str, Any] = {}

    summary: list[tuple[str, Path]] = []
    failures: list[tuple[str, str]] = []
    for svc in args.services:
        print(f"==> Auditing service: {svc}", file=sys.stderr)
        try:
            out_dir = audit_service(
                client,
                svc,
                args.base_url,
                artifacts_root,
                run_ts,
                period,
                advisor_cache,
            )
        except SystemExit as exc:
            print(f"!! {svc}: {exc}", file=sys.stderr)
            failures.append((svc, str(exc)))
            continue
        summary.append((svc, out_dir))
        print(f"   wrote: {out_dir}", file=sys.stderr)

    print("\n=== Summary ===", file=sys.stderr)
    for svc, p in summary:
        print(f"OK  {svc} -> {p}", file=sys.stderr)
    for svc, err in failures:
        print(f"ERR {svc}: {err}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(run())
