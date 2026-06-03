#!/usr/bin/env python3
"""Icinga/Nagios plugin: Nutanix Prism Central recovery point age.

Exit: 0=OK 1=WARN 2=CRIT 3=UNKNOWN
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import ssl
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Any

OK, WARN, CRIT, UNKNOWN = 0, 1, 2, 3


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Check Nutanix VM recovery point age")
    p.add_argument("--host", required=True, help="Prism Central hostname/IP")
    p.add_argument("--username", required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--warn-days", "--warn", dest="warn_days", type=int, default=7)
    p.add_argument("--crit-days", "--critical", "--critical-days", dest="crit_days", type=int, default=0,
                   help="0 disables critical threshold")
    p.add_argument("--page-size", type=int, default=400)
    p.add_argument("--timeout", type=int, default=45)
    p.add_argument("--max-details", type=int, default=5)
    p.add_argument("--workers", type=int, default=16, help="Parallel workers for pages and VM lookups")
    p.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    return p.parse_args()


def ssl_ctx(insecure: bool) -> ssl.SSLContext | None:
    if not insecure:
        return None
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def request(host: str, user: str, pwd: str, path: str, timeout: int, ctx, *,
            payload: dict | None = None, allow_404: bool = False) -> dict[str, Any]:
    auth = base64.b64encode(f"{user}:{pwd}".encode()).decode("ascii")
    headers = {"Accept": "application/json", "Authorization": f"Basic {auth}"}
    data = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(f"https://{host}:9440{path}", data=data,
                                 method="POST" if payload is not None else "GET", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if allow_404 and exc.code == 404:
            return {}
        raise RuntimeError(f"HTTP {exc.code} from {path}: {exc.read().decode('utf-8', 'replace')}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Connection error for {path}: {exc}") from exc


def to_epoch(raw: Any) -> int:
    if raw is None or raw == "":
        return 0
    if isinstance(raw, (int, float)):
        v = int(raw)
    elif str(raw).strip().isdigit():
        v = int(str(raw).strip())
    else:
        t = str(raw).strip()
        try:
            return int(dt.datetime.fromisoformat(t[:-1] + "+00:00" if t.endswith("Z") else t).timestamp())
        except ValueError:
            return 0
    return v // 1_000_000 if v > 1_000_000_000_000_000 else v // 1_000 if v > 1_000_000_000_000 else v


def fetch_all_points(host: str, user: str, pwd: str, page_size: int, timeout: int, ctx, workers: int) -> list[dict]:
    body = lambda offset, length: {  # noqa: E731
        "kind": "vm_recovery_point", "length": length, "offset": offset,
        "sort_attribute": "creation_time", "sort_order": "ASCENDING",
    }
    first = request(host, user, pwd, "/api/nutanix/v3/vm_recovery_points/list", timeout, ctx, payload=body(0, 1))
    total = int(first.get("metadata", {}).get("total_matches", 0))
    if total == 0:
        return []
    offsets = list(range(0, total, page_size))
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(offsets)))) as pool:
        pages = pool.map(lambda o: request(host, user, pwd, "/api/nutanix/v3/vm_recovery_points/list",
                                           timeout, ctx, payload=body(o, page_size)), offsets)
        return [e for page in pages for e in page.get("entities", [])]


def info(entity: dict, now: int) -> dict:
    status = entity.get("status", {})
    spec = entity.get("spec", {})
    meta = entity.get("metadata", {})
    res = status.get("resources", {})
    created = to_epoch(res.get("creation_time_usecs") or res.get("creation_time") or meta.get("creation_time"))
    age = max(0, (now - created) // 86400) if created else 0
    vm = res.get("parent_vm_reference", {}).get("uuid") or spec.get("resources", {}).get("parent_vm_reference", {}).get("uuid") or "unknown"
    return {
        "snapshot_uuid": entity.get("ext_id") or meta.get("uuid") or entity.get("uuid") or "unknown",
        "snapshot_name": entity.get("name") or status.get("name") or spec.get("name") or "unknown",
        "vm_uuid": vm, "vm_name": vm,
        "created_epoch": created, "age_days": int(age),
    }


def resolve_vm_names(host: str, user: str, pwd: str, uuids: list[str], timeout: int, ctx, workers: int) -> dict[str, str]:
    uuids = [u for u in uuids if u and u != "unknown"]
    if not uuids:
        return {}

    def lookup(uuid: str) -> tuple[str, str]:
        try:
            vm = request(host, user, pwd, f"/api/nutanix/v3/vms/{uuid}", timeout, ctx, allow_404=True)
        except RuntimeError:
            return uuid, uuid
        return uuid, vm.get("status", {}).get("name") or vm.get("spec", {}).get("name") or uuid

    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(uuids)))) as pool:
        return dict(pool.map(lookup, uuids))


def fmt_lines(items: list[dict]) -> list[str]:
    return [f"{p['snapshot_uuid']} (vm={p['vm_name']}, age={p['age_days']}d);" for p in items]


def main() -> int:
    a = parse_args()
    if a.warn_days < 0 or a.crit_days < 0:
        print("UNKNOWN - thresholds must be >= 0")
        return UNKNOWN
    if a.crit_days and a.crit_days <= a.warn_days:
        print("UNKNOWN - --crit-days must be greater than --warn-days")
        return UNKNOWN

    now = int(dt.datetime.now(tz=dt.timezone.utc).timestamp())
    ctx = ssl_ctx(a.insecure)

    try:
        points = [info(e, now) for e in fetch_all_points(a.host, a.username, a.password,
                                                          a.page_size, a.timeout, ctx, a.workers)]
    except Exception as exc:
        print(f"UNKNOWN - Failed to query Prism: {exc}")
        return UNKNOWN

    total = len(points)
    if a.crit_days:
        warn = sorted([p for p in points if a.warn_days < p["age_days"] <= a.crit_days],
                      key=lambda x: x["age_days"], reverse=True)
        crit = sorted([p for p in points if p["age_days"] > a.crit_days],
                      key=lambda x: x["age_days"], reverse=True)
    else:
        warn = sorted([p for p in points if p["age_days"] > a.warn_days],
                      key=lambda x: x["age_days"], reverse=True)
        crit = []

    vm_map = resolve_vm_names(a.host, a.username, a.password,
                              sorted({p["vm_uuid"] for p in warn + crit}),
                              a.timeout, ctx, a.workers)
    for p in warn + crit:
        p["vm_name"] = vm_map.get(p["vm_uuid"], p["vm_uuid"])

    oldest = max((p["age_days"] for p in points), default=0)
    perfdata = (f"| total={total} warning_count={len(warn)} critical_count={len(crit)} "
                f"offenders={len(warn) + len(crit)} oldest_days={oldest} warn={a.warn_days}"
                + (f" critical={a.crit_days}" if a.crit_days else ""))

    if crit:
        print(f"CRITICAL - {len(crit)} recovery points older than {a.crit_days}d.")
        if warn:
            print(f"Warning SnapShots (>{a.warn_days}d and <= {a.crit_days}d):")
            print("\n".join(fmt_lines(warn)))
        print(f"Critical SnapShots (>{a.crit_days}d):")
        print("\n".join(fmt_lines(crit)))
        print(perfdata)
        return CRIT

    if warn:
        suffix = f" and up to {a.crit_days}d" if a.crit_days else ""
        print(f"WARNING - {len(warn)} recovery points older than {a.warn_days}d{suffix}.")
        print("Warning SnapShots:")
        print("\n".join(fmt_lines(warn)))
        print(perfdata)
        return WARN

    print(f"OK - No recovery points older than {a.warn_days}d (checked {total}, oldest {oldest}d) {perfdata}")
    return OK


if __name__ == "__main__":
    sys.exit(main())
