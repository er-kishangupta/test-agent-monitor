"""Runbooks: one Markdown file per configured policy, served by the SIEM.

The hand-written file (runbooks/*.md) holds the human procedure. The SIEM appends a generated reference
section built from the live catalog and the live known-environment register, so the runbook cannot
disagree with what the rule actually does or with the values it currently reads.
"""
from __future__ import annotations

import re
from pathlib import Path

from . import catalog as K
from . import config as C

DIR = Path(__file__).resolve().parent.parent / "runbooks"
_ID = re.compile(r"^RB-[A-Z0-9]{1,5}$")


def _parse(text: str) -> tuple[dict, str]:
    meta, body = {}, text
    if text.startswith("---\n"):
        head, _, body = text[4:].partition("\n---\n")
        for line in head.splitlines():
            k, _, v = line.partition(":")
            meta[k.strip()] = v.strip()
    return meta, body.lstrip("\n")


def _split(v: str) -> list[str]:
    return [x.strip() for x in v.split(",") if x.strip() and x.strip().lower() != "none"]


def load_all() -> dict[str, dict]:
    out = {}
    for f in sorted(DIR.glob("RB-*.md")):
        if not _ID.match(f.stem):
            continue
        meta, body = _parse(f.read_text(encoding="utf-8"))
        rules = [] if meta.get("rules") in ("all", "register", None) else _split(meta["rules"])
        out[f.stem] = {"id": f.stem, "title": meta.get("title", f.stem), "scope": meta.get("rules", ""), "rules": rules,
                       "owner": meta.get("owner", ""), "version": meta.get("version", ""), "depends": _split(meta.get("depends", "")),
                       "body": body}
    return out


def for_rule(rule_id: str) -> str | None:
    for rid, r in load_all().items():
        if rule_id in r["rules"]:
            return rid
    return None


def _register_block(keys: list[str]) -> list[dict]:
    rows = []
    for k in keys:
        m = C.ENV_REGISTER.get(k)
        if not m:
            continue
        val = getattr(C, k, None)
        items = sorted(map(str, val)) if isinstance(val, (set, frozenset, tuple, list)) else [str(val)]
        rows.append({"key": k, "status": m.get("status", "assumed"), "owner": m.get("owner", ""), "kind": m.get("kind", "policy"),
                     "why": m.get("why", ""), "count": len(items), "items": items[:12], "more": max(0, len(items) - 12)})
    return rows


def _generated(rb: dict) -> dict:
    gen = {"rules": [], "register": _register_block(rb["depends"])}
    for rid in rb["rules"]:
        cat, logic = K.RULE_CATALOG.get(rid), K.LOGIC.get(rid)
        if not cat:
            continue
        decs = [{"action": K.DECISION_DEFS[d]["action"], "owner": K.DECISION_DEFS[d]["owner"], "why": K.DECISION_DEFS[d]["why"]}
                for d in K.RULE_DECISIONS.get(rid, [])]
        gen["rules"].append({"id": rid, "name": cat["name"], "detects": cat["detects"], "why": cat["why"], "triage": cat["triage"], "contain": cat["contain"],
                             "severity": (logic or {}).get("severity", ""), "techniques": (logic or {}).get("techniques", []),
                             "verified_by": (logic or {}).get("verified_by", ""), "decisions": decs,
                             "response": ["medium and above: page on-call",
                                          "high and critical: quarantine register, suspend the agent session, flag files"
                                          + (", block the package" if rid == "D3" else "") + (", EDR host isolation (host-level)" if rid == "D8" else "")]})
    gen["due"] = K.DECISION_DUE
    return gen


def index() -> list[dict]:
    return [{k: v for k, v in r.items() if k != "body"} for r in load_all().values()]


def get(rid: str) -> dict | None:
    if not _ID.match(rid):
        return None
    rb = load_all().get(rid)
    return {**rb, "generated": _generated(rb)} if rb else None
