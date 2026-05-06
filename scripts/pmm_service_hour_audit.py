#!/usr/bin/env python3
"""
Collect PMM v1 API data for a MySQL service over the last hour and emit a heuristic REPORT.md.
Uses docs/swagger.json contract (Swagger 2); auth: HTTP Basic from cred file or env.
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
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlencode, urlparse


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


def find_mysql_service(
    client: PMMClient, target: str
) -> tuple[dict[str, Any], str]:
    """Return (mysql_service_dict, resolution_note)."""
    status, data = client.request(
        "GET",
        "/v1/inventory/services",
        query={"service_type": "SERVICE_TYPE_MYSQL_SERVICE"},
    )
    if status != 200 or not isinstance(data, dict):
        raise SystemExit(f"ListServices failed: HTTP {status} {data!r}")
    mysql = data.get("mysql") or []
    if not isinstance(mysql, list):
        mysql = []
    for svc in mysql:
        if not isinstance(svc, dict):
            continue
        if svc.get("service_name") == target:
            return svc, "matched service_name in inventory list"
        if svc.get("service_id") == target:
            return svc, "matched service_id in inventory list"
    # Try direct get by id-like target
    st2, one = client.request("GET", f"/v1/inventory/services/{target}")
    if st2 == 200 and isinstance(one, dict) and one.get("mysql"):
        m = one["mysql"]
        if isinstance(m, dict):
            return m, "GET /v1/inventory/services/{id} returned mysql"
    raise SystemExit(
        f"Service {target!r} not found among {len(mysql)} MySQL inventory services."
    )


def labels_for(service_name: str, service_id: str, label_key: str) -> list[dict[str, Any]]:
    return [{"key": label_key, "value": [service_name if label_key == "service_name" else service_id]}]


def period_body(t_from: datetime, t_to: datetime) -> dict[str, Any]:
    return {"period_start_from": rfc3339(t_from), "period_start_to": rfc3339(t_to)}


def sparkline_stats(sparkline: list[Any]) -> dict[str, Any]:
    loads: list[float] = []
    for pt in sparkline or []:
        if not isinstance(pt, dict):
            continue
        v = pt.get("load")
        if isinstance(v, (int, float)) and not math.isnan(float(v)):
            loads.append(float(v))
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
    """Use top-level sparkline if present; else pick per-dimension sparkline with highest CV."""
    if isinstance(resp, dict):
        top = resp.get("sparkline")
        if isinstance(top, list) and len(top) >= 2:
            return sparkline_stats(top), "(service_aggregate)"
    best_cv = -1.0
    best_stats: dict[str, Any] = {"n": 0, "note": "no sparkline"}
    best_dim: Optional[str] = None
    if not isinstance(resp, dict):
        return best_stats, None
    metrics = resp.get("metrics")
    if not isinstance(metrics, dict):
        return best_stats, None
    for dim, cell in metrics.items():
        if not isinstance(cell, dict):
            continue
        sl = cell.get("sparkline")
        if not isinstance(sl, list):
            continue
        st = sparkline_stats(sl)
        cv = st.get("coef_variation")
        if isinstance(cv, float) and not math.isnan(cv) and cv > best_cv:
            best_cv = cv
            best_stats = st
            best_dim = str(dim)
    return best_stats, best_dim


def analyze_report_rows(rows: list[Any], main_metric: str) -> list[str]:
    issues: list[str] = []
    if not rows:
        issues.append("QAN metrics:getReport returned no rows for this window/filters.")
        return issues
    # Dominance: compare top two by primary metric sum if present
    def row_sum(row: dict[str, Any]) -> float:
        m = row.get("metrics") or {}
        if not isinstance(m, dict):
            return 0.0
        for key in (main_metric, "m_query_time_sum", "query_time", "load"):
            cell = m.get(key)
            if isinstance(cell, dict):
                st = cell.get("stats") or {}
                if isinstance(st, dict) and isinstance(st.get("sum"), (int, float)):
                    return float(st["sum"])
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
                f"has m_query_time_sum ~ {s0:.4g} vs second ~ {s1:.4g} (>{5}x)."
            )
    # Tail latency per row
    for row in ranked[:10]:
        dim = row.get("dimension") if isinstance(row, dict) else None
        metrics = (row.get("metrics") or {}) if isinstance(row, dict) else {}
        if not isinstance(metrics, dict):
            continue
        for mname, cell in metrics.items():
            if "time" not in mname and mname not in ("load", "m_lock_time_sum"):
                continue
            if not isinstance(cell, dict):
                continue
            st = cell.get("stats") or {}
            if not isinstance(st, dict):
                continue
            p99 = st.get("p99")
            avg = st.get("avg")
            if isinstance(p99, (int, float)) and isinstance(avg, (int, float)) and avg > 0:
                if float(p99) > 8 * float(avg):
                    issues.append(
                        f"Tail skew on {mname} for queryid={dim!r}: p99={p99} vs avg={avg} (~{float(p99)/float(avg):.1f}x)."
                    )
    return issues


def run() -> int:
    ap = argparse.ArgumentParser(description="PMM last-hour service audit")
    ap.add_argument(
        "service",
        nargs="?",
        default="mvc-lab-db1-mysql",
        help="service_name or service_id (default: mvc-lab-db1-mysql)",
    )
    ap.add_argument(
        "--base-url",
        default=os.environ.get("PMM_BASE_URL", "https://10.30.50.81:8443"),
    )
    ap.add_argument(
        "--cred-file",
        type=Path,
        default=Path(os.environ.get("CRED_FILE", "cred")),
    )
    ap.add_argument(
        "--artifacts",
        type=Path,
        default=Path("artifacts") / "pmm-mvc-lab-db1-mysql",
    )
    args = ap.parse_args()
    repo_root = Path(__file__).resolve().parents[1]
    cred_path = args.cred_file if args.cred_file.is_absolute() else repo_root / args.cred_file
    if not cred_path.is_file():
        raise SystemExit(f"Missing cred file: {cred_path}")
    user, password = load_cred(cred_path)

    ts = utc_now().strftime("%Y%m%dT%H%M%SZ")
    out_dir = (
        args.artifacts
        if args.artifacts.is_absolute()
        else repo_root / args.artifacts / ts
    )
    out_dir.mkdir(parents=True, exist_ok=True)

    t_to = utc_now()
    t_from = t_to - timedelta(hours=1)
    period = period_body(t_from, t_to)

    client = PMMClient(args.base_url, user, password)
    meta: dict[str, Any] = {
        "base_url": args.base_url,
        "service_query": args.service,
        "period_start_from": period["period_start_from"],
        "period_start_to": period["period_start_to"],
        "artifacts_dir": str(out_dir),
    }
    save_json(out_dir, "_run_meta.json", meta)

    svc, note = find_mysql_service(client, args.service)
    save_json(out_dir, "inventory_service_match.json", {"match_note": note, "service": svc})
    sid = svc.get("service_id")
    sname = svc.get("service_name")
    if not sid:
        raise SystemExit("Resolved service has no service_id")

    st, detail = client.request("GET", f"/v1/inventory/services/{sid}")
    save_json(out_dir, "inventory_service_detail.json", {"http_status": st, "body": detail})

    st, inv_agents = client.request(
        "GET", "/v1/inventory/agents", query={"service_id": sid}
    )
    save_json(out_dir, "inventory_agents.json", {"http_status": st, "body": inv_agents})
    slowlog_statuses: list[str] = []
    if isinstance(inv_agents, dict):
        for agent in inv_agents.get("qan_mysql_slowlog_agent") or []:
            if isinstance(agent, dict) and agent.get("status"):
                slowlog_statuses.append(str(agent["status"]))

    st, mgmt_agents = client.request(
        "GET", "/v1/management/agents", query={"service_id": sid}
    )
    save_json(out_dir, "management_agents.json", {"http_status": st, "body": mgmt_agents})

    st, advisors = client.request(
        "GET", "/v1/advisors/checks/failed", query={"service_id": sid}
    )
    save_json(out_dir, "advisors_checks_failed.json", {"http_status": st, "body": advisors})

    st, qhealth = client.request("GET", "/v1/qan/health")
    save_json(out_dir, "qan_health.json", {"http_status": st, "body": qhealth})

    st, metric_names = client.request("POST", "/v1/qan/metrics:getNames", json_body={})
    save_json(out_dir, "qan_metrics_getNames.json", {"http_status": st, "body": metric_names})

    label_key = "service_name"
    label_val = sname or args.service
    qan_labels = labels_for(str(label_val), str(sid), label_key)

    def qan_post(path: str, extra: dict[str, Any]) -> tuple[int, Any]:
        body = {**period, **extra}
        return client.request("POST", path, json_body=body)

    st, filters = qan_post(
        "/v1/qan/metrics:getFilters",
        {"labels": qan_labels},
    )
    save_json(
        out_dir,
        "qan_metrics_getFilters.json",
        {"http_status": st, "body": filters, "labels_attempt": label_key},
    )

    # Retry with service_id label if filters empty or error
    if st != 200 or not (isinstance(filters, dict) and filters.get("labels")):
        label_key = "service_id"
        qan_labels = labels_for(str(label_val), str(sid), label_key)
        st, filters = qan_post("/v1/qan/metrics:getFilters", {"labels": qan_labels})
        save_json(
            out_dir,
            "qan_metrics_getFilters_retry_service_id.json",
            {"http_status": st, "body": filters, "labels_attempt": label_key},
        )

    main_metric = "m_query_time_sum"
    if isinstance(metric_names, dict) and isinstance(metric_names.get("data"), dict):
        names = metric_names["data"]
        for pref in ("m_query_time_sum", "query_time", "load", "m_rows_examined_sum"):
            if pref in names:
                main_metric = pref
                break
        else:
            if names:
                main_metric = next(iter(names.keys()))

    st, metrics = qan_post(
        "/v1/qan:getMetrics",
        {
            "labels": qan_labels,
            "include_only_fields": [main_metric],
            "totals": True,
        },
    )
    save_json(
        out_dir,
        "qan_getMetrics_totals.json",
        {"http_status": st, "body": metrics, "main_metric": main_metric, "labels": label_key},
    )

    st, metrics_ts = qan_post(
        "/v1/qan:getMetrics",
        {
            "labels": qan_labels,
            "include_only_fields": [main_metric],
            "totals": False,
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
        pick_metric_col("m_rows_examined_sum", "rows_examined"),
        pick_metric_col("m_rows_sent_sum", "rows_sent"),
    ):
        if extra and extra not in report_columns:
            report_columns.append(extra)

    report_body: dict[str, Any] = {
        **period,
        "group_by": "queryid",
        "labels": qan_labels,
        "main_metric": main_metric,
        "limit": 25,
        "columns": report_columns,
        "order_by": f"-{main_metric}",
    }
    report_st, report = client.request("POST", "/v1/qan/metrics:getReport", json_body=report_body)
    if report_st != 200:
        rb2 = {k: v for k, v in report_body.items() if k != "order_by"}
        report_st, report = client.request("POST", "/v1/qan/metrics:getReport", json_body=rb2)
    save_json(
        out_dir,
        "qan_metrics_getReport.json",
        {"http_status": report_st, "body": report},
    )

    histogram_files = 0
    top_ids: list[str] = []
    if isinstance(report, dict):
        rows = report.get("rows") or []
        if isinstance(rows, list):
            for row in rows[:3]:
                if isinstance(row, dict):
                    d = row.get("dimension")
                    if isinstance(d, str):
                        top_ids.append(d)
    for i, qid in enumerate(top_ids):
        hist_st, hist = qan_post(
            "/v1/qan:getHistogram",
            {"labels": qan_labels, "queryid": qid},
        )
        save_json(
            out_dir,
            f"qan_getHistogram_{i}.json",
            {"http_status": hist_st, "body": hist, "queryid": qid},
        )
        histogram_files += 1

    # --- Analysis ---
    lines: list[str] = []
    lines.append("# PMM last-hour audit\n")
    lines.append(f"- **Window (UTC):** `{period['period_start_from']}` → `{period['period_start_to']}`\n")
    lines.append(f"- **Base URL:** `{args.base_url}`\n")
    lines.append(f"- **Target:** `{args.service}`\n")
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
        f"- Address: `{svc.get('address')}` port `{svc.get('port')}` version `{svc.get('version')}` "
        f"cluster `{svc.get('cluster')}`\n"
    )

    lines.append("\n## Findings and oddities\n")
    issues: list[str] = []

    if slowlog_statuses and any(s != "AGENT_STATUS_RUNNING" for s in slowlog_statuses):
        issues.append(
            f"QAN MySQL slowlog agent status not RUNNING: {slowlog_statuses} — expect weak or empty QAN data until healthy."
        )

    if report_st != 200:
        issues.append(f"metrics:getReport HTTP {report_st}: {str(report)[:500]}")

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
            if isinstance(st0, dict) and st0.get("cnt") == 0:
                issues.append(
                    "QAN metrics:getReport shows **zero query events** in the window (`cnt=0`) — "
                    "typical if the slowlog agent is not RUNNING or there was no qualifying workload."
                )

    if isinstance(advisors, dict):
        results = advisors.get("results")
        if isinstance(results, list) and results:
            sev_counts: dict[str, int] = {}
            for item in results:
                if not isinstance(item, dict):
                    continue
                sev = str(item.get("severity") or "UNKNOWN")
                sev_counts[sev] = sev_counts.get(sev, 0) + 1
            lines.append(
                f"- Advisor checks in this page: **{len(results)}** items; severity counts: `{sev_counts}`\n"
            )
            warn_cap = 0
            for item in results:
                if not isinstance(item, dict):
                    continue
                if item.get("severity") == "SEVERITY_ERROR":
                    issues.append(
                        f"Advisor ERROR `{item.get('check_name')}`: {item.get('summary')}"
                    )
                elif item.get("severity") == "SEVERITY_WARNING" and warn_cap < 5:
                    issues.append(
                        f"Advisor WARNING `{item.get('check_name')}`: {item.get('summary')}"
                    )
                    warn_cap += 1
        else:
            lines.append("- Advisor response had no `results` list; see JSON file.\n")

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
            f"Bursty load in-window (dim {sl_dim!r}): sparkline max/mean load ratio {sls['max_over_mean']:.2f} (threshold 4)."
        )
    if isinstance(sls.get("coef_variation"), float) and sls["coef_variation"] and sls["coef_variation"] > 1.2:
        issues.append(
            f"High relative volatility (dim {sl_dim!r}): sparkline load CV {sls['coef_variation']:.2f} (threshold 1.2)."
        )
    if sls.get("n") == 0:
        issues.append(
            "No sparkline points parsed from qan_getMetrics_timeseries.json — check label filter or QAN data lag."
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
        "- **Dominant / skewed query:** capture `queryid`, run `EXPLAIN` / `EXPLAIN ANALYZE`, review indexes and row estimates.\n"
    )
    lines.append(
        "- **Burst load:** correlate with deploys/cron jobs; consider rate limits, caching, connection pool sizing.\n"
    )
    lines.append(
        "- **Empty QAN / sparkline:** confirm `pmm-agent` and QAN MySQL agents running (`inventory_agents.json`); verify time on server vs UTC window.\n"
    )
    lines.append(
        "- **Advisor failures:** follow each check remediation text in `advisors_checks_failed.json` (version, security, config).\n"
    )

    report_path = out_dir / "REPORT.md"
    report_path.write_text("".join(lines), encoding="utf-8")
    print(report_path.read_text(encoding="utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
