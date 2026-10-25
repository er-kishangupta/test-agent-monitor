"""Known-environment register with maker-checker change control.

The register (config/environment.json, loaded in config.py) holds the facts the policies depend on: corporate ranges, approved installers,
registries, critical repos. Nothing changes it silently. A change is a PROPOSAL (add / remove an item, or confirm an entry) made by one
person with a reason, usually from a false-positive case, and takes effect only when a DIFFERENT, MORE SENIOR person approves it.
Every step is written to the audit log. State = the proposal list; approved proposals are replayed onto the config at start-up."""
from __future__ import annotations

import datetime as _dt
import ipaddress
import json
import re
import time
from pathlib import Path

from . import config as C
from .audit import AUDIT

ROLE_RANK = {"analyst": 1, "senior": 2, "lead": 3}
ACTOR_RX = re.compile(r"^[A-Za-z0-9._@ -]{1,40}$")
OPS = ("add", "remove", "set", "confirm")


class RegisterError(ValueError):
    def __init__(self, msg: str, code: int = 422):
        super().__init__(msg)
        self.code = code


def norm_actor(actor: str | None, role: str | None) -> tuple[str, str]:
    a = (actor or "").strip()
    r = (role or "analyst").strip().lower()
    return (a if ACTOR_RX.match(a) else "anonymous"), (r if r in ROLE_RANK else "analyst")


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


DEFAULT_REVIEW_DAYS = 90
DUE_SOON_DAYS = 14


def expiry_state(meta: dict, today: _dt.date | None = None) -> dict:
    """Review-by date of a register entry. An allow-list that nobody re-confirms becomes a blind spot, so every entry carries a date.
    Expiry never deletes the value (that would switch a detection off or flood the SOC); it flags the entry for its owner."""
    today = today or _dt.datetime.now(_dt.timezone.utc).date()
    try:
        due = _dt.date.fromisoformat(str(meta.get("review_by", "")))
    except ValueError:
        return {"state": "none", "days_left": None, "review_by": None}
    left = (due - today).days
    return {"state": "expired" if left < 0 else "due_soon" if left <= DUE_SOON_DAYS else "ok", "days_left": left, "review_by": due.isoformat()}


class Register:
    def __init__(self, out_dir: Path | str):
        self.file = Path(out_dir) / "register_proposals.json"
        self.base = {k: (set(v) if isinstance(v, (set, frozenset)) else v) for k, v in ((k, getattr(C, k)) for k in C.ENV_REGISTER)}
        self.proposals: list[dict] = []
        self._expiry_logged: set[tuple] = set()
        try:
            self.proposals = json.loads(self.file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
        for p in self.proposals:
            if p["status"] == "approved":
                self._apply(p, record=False)

    # ---------------------------------------------------------------- views
    def entries(self) -> list[dict]:
        out = []
        for k, meta in C.ENV_REGISTER.items():
            v = getattr(C, k)
            items = sorted(v) if isinstance(v, (set, frozenset)) else list(v) if isinstance(v, tuple) else [v]
            out.append({"key": k, **{x: y for x, y in meta.items()}, "items": items, "expiry": expiry_state(meta),
                        "pending": sum(p["key"] == k and p["status"] == "pending" for p in self.proposals)})
        return out

    def check_expiry(self) -> list[dict]:
        """Entries past their review-by date. Each is written to the audit log once per due date, as an action by the system."""
        late = [{"key": k, **expiry_state(m), "owner": m.get("owner", "")} for k, m in C.ENV_REGISTER.items() if expiry_state(m)["state"] == "expired"]
        for x in late:
            tag = (x["key"], x["review_by"])
            if tag not in self._expiry_logged:
                self._expiry_logged.add(tag)
                AUDIT.log("system", "register_review_overdue", x["key"], {"review_by": x["review_by"], "owner": x["owner"], "days_overdue": -x["days_left"]}, "system")
        return late

    def view(self) -> dict:
        late = self.check_expiry()
        states = [expiry_state(m)["state"] for m in C.ENV_REGISTER.values()]
        return {"file": "config/environment.json", "roles": ROLE_RANK, "entries": self.entries(),
                "proposals": self.proposals[::-1], "unconfirmed": sum(m.get("status") != "confirmed" for m in C.ENV_REGISTER.values()),
                "review": {"expired": len(late), "due_soon": states.count("due_soon"), "default_days": DEFAULT_REVIEW_DAYS,
                           "rule": "Past its review-by date an entry stays in force but is flagged to its owner. Only a maker-checker 'confirm' resets the date."}}

    # ---------------------------------------------------------------- maker
    def propose(self, actor: str, role: str, key: str, op: str, value: str | None, reason: str, case_id: str | None = None, ip: str = "") -> dict:
        actor, role = norm_actor(actor, role)
        if key not in C.ENV_REGISTER:
            raise RegisterError("unknown register entry")
        if op not in OPS:
            raise RegisterError("operation must be add, remove, set or confirm")
        cur = getattr(C, key)
        coll = isinstance(cur, (set, frozenset, tuple))
        value = (value or "").strip()
        if op in ("add", "remove") and not coll:
            raise RegisterError("this entry is a single value: use set")
        if op == "set" and coll:
            raise RegisterError("this entry is a list: use add or remove")
        if op != "confirm" and not value:
            raise RegisterError("a value is required")
        if len(value) > 200 or len(reason.strip()) < 10:
            raise RegisterError("value max 200 chars; reason must say why (at least 10 chars)")
        if key == "CORP_SOURCE_CIDRS" and op == "add":
            try:
                net = ipaddress.ip_network(value, strict=False)
            except ValueError:
                raise RegisterError("not a valid CIDR range")
            if net.prefixlen < 8:
                raise RegisterError("range too broad (/8 or wider would make most of the internet 'corporate')")
        if op == "remove" and value not in (cur if coll else []):
            raise RegisterError("that item is not in the entry")
        if op == "add" and value in cur:
            raise RegisterError("already present")
        if any(p["status"] == "pending" and (p["key"], p["op"], p["value"]) == (key, op, value) for p in self.proposals):
            raise RegisterError("an identical proposal is already pending", 409)
        p = {"id": f"RP-{len(self.proposals) + 1:03d}", "ts": _now(), "key": key, "op": op, "value": value, "reason": reason.strip()[:300], "case_id": case_id,
             "maker": actor, "maker_role": role, "status": "pending", "checker": None, "checker_role": None, "decided": None, "decision_note": None}
        self.proposals.append(p)
        self._save()
        AUDIT.log(actor, "register_proposed", p["id"], {"key": key, "op": op, "value": value, "case": case_id}, role, ip=ip)
        return p

    # ---------------------------------------------------------------- checker
    def decide(self, pid: str, actor: str, role: str, decision: str, note: str | None, ip: str = "") -> dict:
        actor, role = norm_actor(actor, role)
        p = next((x for x in self.proposals if x["id"] == pid), None)
        if not p:
            raise RegisterError("proposal not found", 404)
        if p["status"] != "pending":
            raise RegisterError("already decided", 409)
        if decision not in ("approve", "reject"):
            raise RegisterError("decision must be approve or reject")
        problem = None
        if actor == p["maker"]:
            problem = "maker-checker: you cannot decide your own proposal"
        elif decision == "approve" and ROLE_RANK[role] <= ROLE_RANK[p["maker_role"]] and role != "lead":
            problem = f"maker-checker: approval needs a more senior role than the maker ({p['maker_role']})"
        if problem:
            AUDIT.log(actor, "register_decision_refused", pid, {"decision": decision, "reason": problem}, role, outcome="refused", ip=ip)
            raise RegisterError(problem, 403)
        p.update(status="approved" if decision == "approve" else "rejected", checker=actor, checker_role=role, decided=_now(), decision_note=(note or "")[:300] or None)
        if decision == "approve":
            self._apply(p)
        self._save()
        AUDIT.log(actor, f"register_{p['status']}", pid, {"key": p["key"], "op": p["op"], "value": p["value"], "maker": p["maker"], "note": p["decision_note"]}, role, ip=ip)
        return p

    # ---------------------------------------------------------------- effect
    def _apply(self, p: dict, record: bool = True) -> None:
        key, op, val = p["key"], p["op"], p["value"]
        cur = getattr(C, key)
        if op == "add":
            new = type(cur)(set(cur) | {val}) if isinstance(cur, (set, frozenset)) else tuple(list(cur) + [val])
            setattr(C, key, new)
        elif op == "remove":
            new = type(cur)(set(cur) - {val}) if isinstance(cur, (set, frozenset)) else tuple(x for x in cur if x != val)
            setattr(C, key, new)
        elif op == "set":
            setattr(C, key, val)
        meta = C.ENV_REGISTER[key]
        if op == "confirm":
            meta.update(status="confirmed", confirmed_by=f"{p['maker']} / {p['checker']}", confirmed_on=p["decided"])
            try:
                base = _dt.date.fromisoformat(p["decided"][:10])
            except (TypeError, ValueError):
                base = _dt.datetime.now(_dt.timezone.utc).date()
            meta["review_by"] = (base + _dt.timedelta(days=int(meta.get("review_days") or DEFAULT_REVIEW_DAYS))).isoformat()
        now = getattr(C, key)
        meta["count"] = len(now) if hasattr(now, "__len__") and not isinstance(now, str) else 1
        meta.setdefault("changes", []).append({"id": p["id"], "op": op, "value": val, "maker": p["maker"], "checker": p["checker"], "on": p["decided"]})

    def _save(self) -> None:
        try:
            self.file.write_text(json.dumps(self.proposals, indent=1), encoding="utf-8")
        except OSError:
            pass
