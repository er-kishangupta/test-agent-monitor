"""Intel and enrichment list: one uploaded list of internet IPs / hostnames, internal hosts and users that gives an analyst context.

ENRICHMENT ONLY. A match is shown on the case ("this IP is on feed X, high confidence", "this host is critical, owner Platform") and can be
retro-hunted over what the monitor still holds. A match never fires an alert, never changes a priority and never suppresses anything: the
detection logic stays deterministic and reviewable. Every change is written to the audit log with who, how many rows and which source.

Row format (CSV with this header, or a JSON list of objects with the same keys):
  type        ip | cidr | domain | host | user
  value       the indicator (domain also matches its sub-domains; cidr matches any address inside it)
  kind        threat (bad) | network (one of our network zones, a cidr row) | asset (our host or system) | identity (our user or service) | benign (known good, e.g. corporate NAT)
  tag         short label, e.g. "C2 infrastructure", "critical host", "third-party developer"
  source      where it came from, e.g. "FS-ISAC feed 2026-10", "CMDB", "HR export"
  confidence  low | medium | high   (threat and benign rows)
  owner       who to ask                 (asset and identity rows)
  criticality low | medium | high | critical
  expires     YYYY-MM-DD, after which the row is shown as expired and no longer matched
  note        free text, max 200 characters
Optional context columns, the kind of thing a CMDB, IPAM or HR/IAM export carries (all free text, all optional):
  zone        network zone, e.g. "VPN", "build", "production"        (network and asset rows)
  environment prod | test | dev | corp | vdi | dmz                    (network and asset rows)
  address     the host's IP address                                 (asset rows: an alert that names only the IP still finds the host)
  os          operating system                                      (asset rows)
  service     business service the asset supports                   (asset rows)
  data_class  what it holds, e.g. "customer PII", "secrets"         (asset rows)
  department  team or business unit                                 (identity rows)
In production these columns are filled by scheduled pulls from the CMDB, IPAM, IdP/HR and a threat-intel platform; here they arrive as an upload.
"""
from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import json
import re
import threading
from datetime import date, datetime, timezone
from pathlib import Path

TYPES = ("ip", "cidr", "domain", "host", "user")
KINDS = ("threat", "network", "asset", "identity", "benign")
CONTEXT = ("zone", "environment", "address", "os", "service", "data_class", "department")
LEVELS = ("low", "medium", "high", "critical")
CONF = ("low", "medium", "high")
MAX_ROWS = 5000
MAX_BYTES = 1_000_000
DOMAIN_RX = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
HOST_RX = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
USER_RX = re.compile(r"^[a-z0-9][a-z0-9._@-]{0,63}$")
IPV4_RX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HOSTNAME_RX = re.compile(r"\b(?:[a-z0-9-]{1,63}\.)+[a-z]{2,24}\b")
CTRL = re.compile(r"[\x00-\x1f\x7f]")
TEMPLATE = "type,value,kind,tag,source,confidence,owner,criticality,expires,note," + ",".join(CONTEXT) + "\n"


class IntelError(ValueError):
    pass


def _clean(v, n: int) -> str:
    return CTRL.sub(" ", str(v or "")).strip()[:n]


def _today() -> date:
    return datetime.now(timezone.utc).date()


def normalise(row: dict) -> dict:
    """Validate one row. Raises IntelError with the reason."""
    t = _clean(row.get("type"), 10).lower()
    v = _clean(row.get("value"), 253).lower()
    kind = _clean(row.get("kind"), 10).lower() or "threat"
    if t not in TYPES:
        raise IntelError(f"type must be one of {', '.join(TYPES)}")
    if kind not in KINDS:
        raise IntelError(f"kind must be one of {', '.join(KINDS)}")
    if t == "ip":
        try:
            v = str(ipaddress.ip_address(v))
        except ValueError:
            raise IntelError("not a valid IP address")
    elif t == "cidr":
        try:
            net = ipaddress.ip_network(v, strict=False)
        except ValueError:
            raise IntelError("not a valid CIDR range")
        if net.prefixlen < (8 if net.version == 4 else 32):
            raise IntelError("range too broad (IPv4 /8 or wider, IPv6 /32 or wider)")
        v = str(net)
    elif t == "domain":
        v = v.rstrip(".")
        if not DOMAIN_RX.match(v):
            raise IntelError("not a valid domain name")
    elif t == "host" and not HOST_RX.match(v):
        raise IntelError("not a valid host name")
    elif t == "user" and not USER_RX.match(v):
        raise IntelError("not a valid user name")
    conf = _clean(row.get("confidence"), 10).lower()
    crit = _clean(row.get("criticality"), 10).lower()
    if conf and conf not in CONF:
        raise IntelError("confidence must be low, medium or high")
    if crit and crit not in LEVELS:
        raise IntelError("criticality must be low, medium, high or critical")
    ctx = {k: _clean(row.get(k), 60) for k in CONTEXT}
    if ctx["address"]:
        try:
            ctx["address"] = str(ipaddress.ip_address(ctx["address"].lower()))
        except ValueError:
            raise IntelError("address must be a valid IP address")
    if kind == "network" and t != "cidr":
        raise IntelError("a network row must have type cidr")
    exp = _clean(row.get("expires"), 10)
    if exp:
        try:
            date.fromisoformat(exp)
        except ValueError:
            raise IntelError("expires must be YYYY-MM-DD")
    return {"type": t, "value": v, "kind": kind, "tag": _clean(row.get("tag"), 60), "source": _clean(row.get("source"), 60) or "uploaded list",
            "confidence": conf, "owner": _clean(row.get("owner"), 60), "criticality": crit, "expires": exp, "note": _clean(row.get("note"), 200), **ctx}


def parse(text: str) -> list[dict]:
    """CSV (with header) or JSON list. Returns raw dict rows; validation happens per row in add_many."""
    text = (text or "").strip().lstrip("﻿")
    if not text:
        raise IntelError("empty upload")
    if text[0] in "[{":
        try:
            data = json.loads(text)
        except ValueError:
            raise IntelError("invalid JSON")
        rows = data.get("entries") if isinstance(data, dict) else data
        if not isinstance(rows, list) or not all(isinstance(r, dict) for r in rows):
            raise IntelError("JSON must be a list of objects")
        return rows
    rd = csv.DictReader(io.StringIO(text))
    if not rd.fieldnames or "type" not in [f.strip().lower() for f in rd.fieldnames] or "value" not in [f.strip().lower() for f in rd.fieldnames]:
        raise IntelError("CSV needs a header row with at least: type,value")
    return [{(k or "").strip().lower(): v for k, v in r.items()} for r in rd]


def entry_id(t: str, v: str) -> str:
    return "I-" + hashlib.sha256(f"{t}|{v}".encode()).hexdigest()[:8]


class IntelStore:
    def __init__(self, out_dir: Path | str):
        self.file = Path(out_dir) / "intel_list.json"
        self.lock = threading.Lock()
        self.entries: dict[str, dict] = {}
        try:
            for e in json.loads(self.file.read_text(encoding="utf-8")):
                self.entries[e["id"]] = e
        except (OSError, ValueError, KeyError):
            pass

    def _save(self) -> None:
        try:
            self.file.write_text(json.dumps(list(self.entries.values()), indent=1), encoding="utf-8")
        except OSError:
            pass

    def state(self, e: dict, today: date | None = None) -> str:
        if e.get("expires"):
            try:
                if date.fromisoformat(e["expires"]) < (today or _today()):
                    return "expired"
            except ValueError:
                pass
        return "active"

    # ---------------------------------------------------------------- change
    def add_many(self, rows: list[dict], actor: str, label: str = "") -> dict:
        if len(rows) > MAX_ROWS:
            raise IntelError(f"too many rows (max {MAX_ROWS} per upload)")
        added = updated = 0
        rejected = []
        with self.lock:
            for i, raw in enumerate(rows, 1):
                try:
                    r = normalise(raw)
                except IntelError as ex:
                    if len(rejected) < 25:
                        rejected.append({"row": i, "value": _clean(raw.get("value"), 60), "reason": str(ex)})
                    continue
                eid = entry_id(r["type"], r["value"])
                new = eid not in self.entries
                self.entries[eid] = {"id": eid, **r, "added_by": actor, "added": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "list": _clean(label, 60)}
                added += new
                updated += not new
            self._save()
        return {"added": added, "updated": updated, "rejected": rejected, "rejected_count": len(rows) - added - updated, "total": len(self.entries)}

    def remove(self, eid: str) -> dict | None:
        with self.lock:
            e = self.entries.pop(eid, None)
            if e:
                self._save()
            return e

    def clear(self) -> int:
        with self.lock:
            n = len(self.entries)
            self.entries.clear()
            self._save()
            return n

    # ---------------------------------------------------------------- read
    def view(self) -> dict:
        rows = [{**e, "state": self.state(e)} for e in self.entries.values()]
        rows.sort(key=lambda e: (e["kind"], e["type"], e["value"]))
        counts = {k: sum(r["kind"] == k and r["state"] == "active" for r in rows) for k in KINDS}
        return {"entries": rows, "counts": counts, "expired": sum(r["state"] == "expired" for r in rows), "total": len(rows),
                "template": TEMPLATE, "max_rows": MAX_ROWS,
                "rules": ["Enrichment only: a match adds context to a case, it never fires, suppresses or re-prioritises an alert.",
                          "Expired rows stay visible but are no longer matched.", "Every upload and removal is in the audit log."]}

    def _active(self) -> list[dict]:
        return [e for e in self.entries.values() if self.state(e) == "active"]

    def match(self, typ: str, value: str) -> list[dict]:
        """Rows that apply to one value. ip: exact or inside a cidr row. domain: exact or sub-domain of a domain row."""
        v = (value or "").strip().lower().rstrip(".")
        if not v:
            return []
        out = []
        ip = None
        if typ == "ip":
            try:
                ip = ipaddress.ip_address(v)
            except ValueError:
                return []
        for e in self._active():
            et = e["type"]
            if typ == "ip" and ((et == "ip" and e["value"] == v) or (et == "cidr" and ip.version == ipaddress.ip_network(e["value"]).version and ip in ipaddress.ip_network(e["value"]))):
                out.append(e)
            elif typ == "domain" and et == "domain" and (v == e["value"] or v.endswith("." + e["value"])):
                out.append(e)
            elif typ in ("host", "user") and et == typ and e["value"] == v:
                out.append(e)
            elif typ == "ip" and et == "host" and e.get("address") == str(ip):       # an alert that names only the address still finds the host
                out.append(e)
        return out

    def enrich(self, entities: list[tuple[str, str, str]]) -> dict:
        """entities: (type, value, where). Returns de-duplicated matches with the entity they matched on."""
        index: dict[tuple, dict] = {}
        matches = []
        for typ, val, where in entities:
            for e in self.match(typ, val):
                k = (e["id"], where if typ in ("user", "host") else "evidence")
                if k in index:                           # one row per intel entry per place: 24 DNS look-ups under one bad domain are one finding
                    index[k]["times"] += 1
                    continue
                index[k] = {"id": e["id"], "matched": val, "times": 1, "on": where, "type": e["type"], "value": e["value"], "kind": e["kind"], "tag": e["tag"],
                            "source": e["source"], "confidence": e["confidence"], "owner": e["owner"], "criticality": e["criticality"],
                            "expires": e["expires"], "note": e["note"], **{c: e.get(c, "") for c in CONTEXT}}
                matches.append(index[k])
        order = {k: i for i, k in enumerate(KINDS)}
        matches.sort(key=lambda m: (order[m["kind"]], m["on"], m["matched"]))
        return {"matches": matches, "counts": {k: sum(m["kind"] == k for m in matches) for k in KINDS}}


def case_entities(case: dict, alerts: list[dict], graph: dict | None, session: dict | None) -> list[tuple[str, str, str]]:
    """Everything in a case that an intel row could describe: user, host, and every address or name that appears in its evidence."""
    ents: list[tuple[str, str, str]] = []
    if case.get("user"):
        ents.append(("user", case["user"], "case user"))
    if case.get("host"):
        ents.append(("host", case["host"], "case host"))
    texts: list[str] = []
    for a in alerts:
        ev = a.get("evidence", {}) or {}
        texts += [str(ev.get("snippet", "")), a.get("title", "")]
    if session:
        texts += [str(e.get("summary", "")) for e in list(session.get("events", []))]
        for r in list(session.get("raw", [])):
            d = r.get("data", {}) if isinstance(r, dict) else {}
            texts += [str(v) for v in d.values() if isinstance(v, (str, int))]
            if isinstance(r, dict) and r.get("user"):
                ents.append(("user", r["user"], "event user"))
    for i in (graph or {}).get("iocs", []):
        if i["type"] in ("ip", "domain"):
            ents.append((i["type"], i["value"], "evidence"))
        elif i["type"] == "url":
            m = re.search(r"//([^/:@]+@)?([^/:]+)", i["value"]) or re.search(r"@([^:/]+)[:/]", i["value"])
            if m:
                ents.append(("domain", m.group(m.lastindex).lower(), "evidence"))
    blob = " ".join(texts).lower()
    for ip in set(IPV4_RX.findall(blob)):
        ents.append(("ip", ip, "evidence"))
    for h in set(HOSTNAME_RX.findall(blob)):
        ents.append(("domain", h, "evidence"))
    uniq, out = set(), []
    for e in ents:
        if (e[0], e[1].lower(), e[2]) not in uniq:
            uniq.add((e[0], e[1].lower(), e[2]))
            out.append(e)
    return out[:300]


def retro_hunt(store: IntelStore, engine) -> dict:
    """Search what the monitor still holds (all alerts, per-session timelines, last raw events, host and user inventory) for every active row.
    Production does this over the SIEM's hot, warm and cold tiers; here the horizon is the in-memory state, and the result says so."""
    hits, scanned = [], {"alerts": len(engine.alerts), "sessions": len(engine.sessions), "events": 0}
    by_case = {c["session_id"]: c["case_id"] for c in engine.cases.values()}

    def add(e, where, ts, ev, field):
        hits.append({"id": e["id"], "value": e["value"], "kind": e["kind"], "tag": e["tag"], "confidence": e["confidence"], "where": where, "ts": ts, "event_id": ev, "field": field})

    for a in engine.alerts:
        ev = a.get("evidence", {}) or {}
        blob = f"{ev.get('snippet', '')} {a.get('title', '')}".lower()
        where = by_case.get(a["session_id"], a["session_id"])
        for t, vals in (("ip", IPV4_RX.findall(blob)), ("domain", HOSTNAME_RX.findall(blob))):
            for v in set(vals):
                for e in store.match(t, v):
                    add(e, f"alert {a['alert_id']} · {where}", a["ts"], (ev.get("event_ids") or [""])[0], f"evidence ({v})")
        for t, v in (("user", a.get("user")), ("host", a.get("host"))):
            for e in store.match(t, v or ""):
                add(e, f"alert {a['alert_id']} · {where}", a["ts"], (ev.get("event_ids") or [""])[0], t)
    for sid, s in engine.sessions.items():
        where = by_case.get(sid, sid)
        for ev in list(s.get("events", [])):
            scanned["events"] += 1
            blob = str(ev.get("summary", "")).lower()
            for t, vals in (("ip", IPV4_RX.findall(blob)), ("domain", HOSTNAME_RX.findall(blob))):
                for v in set(vals):
                    for e in store.match(t, v):
                        add(e, f"session {where}", ev.get("ts"), ev.get("event_id"), f"{ev.get('type')} ({v})")
    seen = set()
    for kind_t, coll in (("host", engine.hosts), ("user", {u for u in (s.get("user") for s in engine.sessions.values()) if u})):
        for v in coll:
            for e in store.match(kind_t, v):
                if e["kind"] in ("threat",):
                    add(e, f"{kind_t} inventory", None, None, kind_t)
    uniq = {}
    for h in hits:
        uniq[(h["id"], h["where"], h["event_id"], h["field"])] = h
    out = sorted(uniq.values(), key=lambda h: ({"threat": 0, "network": 1, "asset": 2, "identity": 3, "benign": 4}.get(h["kind"], 5), h["where"]))
    # benign rows (corporate NAT etc.) match thousands of events and teach the analyst nothing: count them, do not list them
    shown = [h for h in out if h["kind"] not in ("benign", "network")]
    agg: dict[str, dict] = {}
    for h in shown:
        g = agg.setdefault(h["id"], {"id": h["id"], "value": h["value"], "kind": h["kind"], "tag": h["tag"], "confidence": h["confidence"], "count": 0, "where": set()})
        g["count"] += 1
        g["where"].add(h["where"].split(" · ")[-1])
    by_ioc = sorted(({**g, "where": sorted(g["where"])} for g in agg.values()), key=lambda g: ({"threat": 0, "network": 1, "asset": 2, "identity": 3}.get(g["kind"], 4), -g["count"]))
    return {"by_ioc": by_ioc, "hits": shown[:200], "hit_total": len(shown), "benign_matches": len(out) - len(shown), "scanned": scanned, "rows_searched": len(store._active()),
            "horizon": "In-memory state only: every alert, each session's timeline and its last raw events. Production runs the same search over the SIEM's hot, warm and cold tiers."}
