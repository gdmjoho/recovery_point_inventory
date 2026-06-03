#!/usr/bin/env python3
from __future__ import annotations

import base64
import csv
import json
import logging
import os
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

API = "/api/nutanix/v3"
RETRYABLE = {408, 429, 500, 502, 503, 504}
SIZE_KEYS = ("size_bytes", "total_size_bytes", "consumed_size_bytes",
             "logical_size_bytes", "physical_size_bytes", "storage_usage_bytes")
CSV_HEADER = ["Snapshot ID", "Snapshot name", "VM name", "VM exists",
              "Snapshot size (GiB)", "Snapshot age (days)"]

logging.basicConfig(level=os.environ.get("NTNX_RP_LOG_LEVEL", "INFO").upper(),
                    format="%(asctime)s %(levelname)s %(message)s", stream=sys.stderr)
log = logging.getLogger("nutanix_rp_pipeline")


def dig(obj: Any, *path: str, default: Any = None) -> Any:
    for k in path:
        if not isinstance(obj, dict) or k not in obj:
            return default
        obj = obj[k]
    return obj


def to_epoch(raw: Any) -> int:
    if raw is None or raw == "":
        return 0
    if isinstance(raw, (int, float)):
        ts = int(raw)
    elif str(raw).strip().isdigit():
        ts = int(str(raw).strip())
    else:
        try:
            t = str(raw).strip()
            dt = datetime.fromisoformat(t[:-1] + "+00:00" if t.endswith("Z") else t)
            return int((dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp())
        except ValueError:
            return 0
    return ts // 1_000_000 if ts > 1_000_000_000_000_000 else ts // 1_000 if ts > 1_000_000_000_000 else ts


def mkctx(validate: bool) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if not validate:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def request(req: Request, timeout: int, ctx: ssl.SSLContext, retries: int, backoff: float) -> tuple[int, dict[str, Any]]:
    attempts = max(1, retries)
    for i in range(attempts):
        try:
            with urlopen(req, timeout=timeout, context=ctx) as r:
                body = r.read().decode("utf-8", "replace")
                return int(getattr(r, "status", 200)), (json.loads(body) if body else {})
        except HTTPError as e:
            body = ""
            try:
                body = e.read().decode("utf-8", "replace")
            except OSError:
                pass
            if e.code in RETRYABLE and i < attempts - 1:
                log.warning("HTTP %s %s (try %d/%d)", e.code, req.full_url, i + 1, attempts)
                time.sleep(backoff * (2 ** i))
                continue
            log.error("HTTP %s %s: %s", e.code, req.full_url, body[:200])
            try:
                return int(e.code), json.loads(body) if body else {}
            except json.JSONDecodeError:
                return int(e.code), {}
        except (URLError, TimeoutError, ssl.SSLError, ConnectionError) as exc:
            if i < attempts - 1:
                log.warning("Net err %s (try %d/%d): %s", req.full_url, i + 1, attempts, exc)
                time.sleep(backoff * (2 ** i))
                continue
            log.error("Net err %s: %s", req.full_url, exc)
            return 0, {}
        except json.JSONDecodeError as exc:
            log.warning("Bad JSON from %s: %s", req.full_url, exc)
            return 0, {}
    return 0, {}


def parse_size(g: dict[str, Any]) -> int:
    gr = g.get("group_results") or [{}]
    data = gr[0].get("entity_results", [{}])[0].get("data", []) if isinstance(gr[0], dict) else []
    for entry in data if isinstance(data, list) else []:
        if isinstance(entry, dict) and entry.get("name") == "snapshot_exclusive_user_bytes":
            outer = entry.get("values") or [{}]
            inner = outer[0].get("values", []) if isinstance(outer[0], dict) else []
            v = inner[0] if inner else 0
            return int(v) if isinstance(v, (int, float)) else (int(v) if str(v).strip().isdigit() else 0)
    return 0


def parallel(items: list[str], fn: Callable, workers: int, skip_none: bool = False) -> dict[str, Any]:
    if not items:
        return {}
    out: dict[str, Any] = {}
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(items)))) as pool:
        for fut in as_completed([pool.submit(fn, x) for x in items]):
            k, v = fut.result()
            if not (skip_none and v is None):
                out[str(k)] = v
    return out


def normalize(raw: list, cutoff: int, now: int) -> tuple[int, list[dict], set[str], set[str]]:
    old: list[dict] = []
    vm_ids: set[str] = set()
    snap_ids: set[str] = set()
    total = 0
    for item in raw:
        if not isinstance(item, dict):
            continue
        total += 1
        c_epoch = to_epoch(dig(item, "status", "resources", "creation_time_usecs")
                           or dig(item, "status", "resources", "creation_time")
                           or dig(item, "metadata", "creation_time", default=""))
        if not (0 < c_epoch < cutoff):
            continue
        sid = item.get("ext_id") or dig(item, "metadata", "uuid") or item.get("uuid") or "unknown"
        vm = (dig(item, "status", "resources", "parent_vm_reference", "uuid")
              or dig(item, "spec", "resources", "parent_vm_reference", "uuid") or "unknown")
        size_fb = next((dig(item, "status", "resources", k) for k in SIZE_KEYS
                        if dig(item, "status", "resources", k)), 0)
        old.append({
            "name": item.get("name") or dig(item, "status", "name") or dig(item, "spec", "name") or "unknown",
            "ext_id": sid, "vm_uuid": vm, "size_fb": int(size_fb or 0),
            "created_epoch": c_epoch, "age_days": int((now - c_epoch) / 86400),
        })
        if sid != "unknown":
            snap_ids.add(str(sid))
        if vm != "unknown":
            vm_ids.add(str(vm))
    old.sort(key=lambda x: x["created_epoch"])
    return total, old, vm_ids, snap_ids


def enrich(pc_ip: str, user: str, pwd: str, vm_ids: list[str], snap_ids: list[str],
           timeout: int, workers: int, ctx, retries: int, backoff: float) -> tuple[dict, dict]:
    total = len(vm_ids) + len(snap_ids)
    if not total:
        return {}, {}
    auth = base64.b64encode(f"{user}:{pwd}".encode()).decode("ascii")
    vm_h = {"Accept": "application/json", "Authorization": f"Basic {auth}"}
    gr_h = {**vm_h, "Content-Type": "application/json"}

    def vm_w(vm_id: str) -> tuple[str, str | None]:
        req = Request(f"https://{pc_ip}:9440{API}/vms/{quote(vm_id, safe='')}", headers=vm_h, method="GET")
        s, d = request(req, timeout, ctx, retries, backoff)
        name = dig(d, "status", "name") or dig(d, "spec", "name")
        return vm_id, str(name) if s == 200 and name else None

    def sz_w(sid: str) -> tuple[str, int]:
        body = json.dumps({
            "entity_type": "vm_recovery_point", "group_member_count": 1, "group_member_offset": 0,
            "availability_zone_scope": "LOCAL",
            "group_member_attributes": [{"attribute": "uuid"}, {"attribute": "snapshot_exclusive_user_bytes"}],
            "filter_criteria": f"uuid=={sid}",
        }).encode("utf-8")
        req = Request(f"https://{pc_ip}:9440{API}/groups", data=body, headers=gr_h, method="POST")
        s, d = request(req, timeout, ctx, retries, backoff)
        return sid, parse_size(d) if s == 200 else 0

    if not vm_ids:
        vw, sw = 1, max(1, workers)
    elif not snap_ids:
        vw, sw = max(1, workers), 1
    else:
        vw = max(1, min(workers - 1, round(workers * len(vm_ids) / total)))
        sw = max(1, workers - vw)
    with ThreadPoolExecutor(max_workers=2) as top:
        vf = top.submit(parallel, vm_ids, vm_w, vw, True)
        sf = top.submit(parallel, snap_ids, sz_w, sw, False)
        return vf.result(), {k: int(v) for k, v in sf.result().items()}


def build_human(old: list[dict], vm_map: dict, size_map: dict) -> list[dict]:
    rows = []
    for x in old:
        sid, vm = str(x["ext_id"]), str(x["vm_uuid"])
        size_b = int(size_map.get(sid, x["size_fb"]) or 0)
        rows.append({
            "snapshot_id": sid, "snapshot_name": str(x["name"]),
            "vm_name": str(vm_map.get(vm, vm)), "vm_exists": "yes" if vm in vm_map else "no",
            "snapshot_size_gib": round(size_b / 1024 ** 3, 2) if size_b > 0 else "unknown",
            "snapshot_age": int(x["age_days"] or 0),
        })
    return rows


def write_csv(path: str, rows: list[dict]) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh, quoting=csv.QUOTE_MINIMAL)
        w.writerow(CSV_HEADER)
        for r in rows:
            w.writerow([r["snapshot_id"], r["snapshot_name"], r["vm_name"],
                        r["vm_exists"], r["snapshot_size_gib"], r["snapshot_age"]])
    log.info("Wrote CSV %s (%d rows)", path, len(rows))


def main() -> int:
    p = json.load(sys.stdin)
    raw = p.get("recovery_points_raw", [])
    csv_path = str(p.get("csv_path", "")).strip()
    log.info("Pipeline start: %d raw points", len(raw))

    total, old, vm_ids, snap_ids = normalize(raw, int(p.get("cutoff_epoch", 0)), int(p.get("now_epoch", 0)))
    log.info("Filtered %d old points. Enriching %d VMs / %d snapshots", len(old), len(vm_ids), len(snap_ids))

    vm_map, size_map = enrich(
        str(p.get("pc_ip", "")), str(p.get("username", "")), str(p.get("password", "")),
        list(vm_ids), list(snap_ids),
        int(p.get("timeout", 90)), int(p.get("max_workers", 16)),
        mkctx(bool(p.get("validate_certs", False))),
        int(p.get("retry_attempts", 3)), float(p.get("retry_backoff_seconds", 0.5)),
    )
    log.info("Enrichment done: %d names, %d sizes", len(vm_map), len(size_map))

    human = build_human(old, vm_map, size_map)
    if csv_path:
        write_csv(csv_path, human)

    json.dump({
        "normalized_count": total, "old_recovery_points_count": len(old),
        "old_recovery_points_human": human,
        "csv_path": csv_path or None, "csv_written": bool(csv_path),
    }, sys.stdout, ensure_ascii=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
