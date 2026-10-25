"""Audit trail for the monitor itself: who did what, when, from where, and what the system did on its own.

Append-only NDJSON where every record carries the SHA-256 of the previous record, so deleting or editing a line breaks the chain
and `verify()` says where. It is deliberately separate from the response files (`Reset` never clears it).
Production: ship the same records to the WORM/immutable store of the central SIEM; a local file only proves tampering to someone who
also holds a trusted copy of the latest hash."""
from __future__ import annotations

import hashlib
import json
import logging
import tempfile
import threading
import time
from collections import deque
from pathlib import Path

GENESIS = "0" * 64
MAX_DETAIL = 300


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _clean(v):
    if isinstance(v, str):
        return v[:MAX_DETAIL]
    if isinstance(v, dict):
        return {str(k)[:40]: _clean(x) for k, x in list(v.items())[:20]}
    if isinstance(v, (list, tuple)):
        return [_clean(x) for x in list(v)[:20]]
    return v


class Audit:
    def __init__(self) -> None:
        self.enabled = False
        self.path: Path | None = None
        self.seq = 0
        self.last = GENESIS
        self.recent: deque = deque(maxlen=3000)
        self.lock = threading.Lock()

    def configure(self, out_dir: Path | str) -> None:
        d = Path(out_dir)
        try:
            d.mkdir(parents=True, exist_ok=True)
            (d / ".audit-test").write_text("ok")
            (d / ".audit-test").unlink()
        except OSError:
            d = Path(tempfile.mkdtemp(prefix="agentmon_audit_"))
            logging.warning("OUT_DIR not writable; the audit log is in %s (inside the container)", d)
        self.path = d / "audit.ndjson"
        self.seq, self.last = 0, GENESIS
        self.recent.clear()
        if self.path.exists():                        # resume the chain across restarts
            for line in self.path.read_text(encoding="utf-8").splitlines():
                try:
                    r = json.loads(line)
                except ValueError:
                    continue
                self.seq, self.last = r.get("seq", self.seq), r.get("hash", self.last)
                self.recent.append(r)
        self.enabled = True
        self.log("system", "monitor_started", detail={"audit_resumed_at_seq": self.seq})

    def log(self, actor: str, action: str, target: str = "", detail: dict | None = None, role: str = "", outcome: str = "ok", ip: str = "") -> dict | None:
        if not self.enabled or not self.path:
            return None
        with self.lock:
            self.seq += 1
            rec = {"seq": self.seq, "ts": _now(), "actor": actor or "unknown", "role": role, "action": action, "target": target[:80],
                   "outcome": outcome, "ip": ip, "detail": _clean(detail or {}), "prev": self.last}
            rec["hash"] = hashlib.sha256((self.last + json.dumps(rec, sort_keys=True, separators=(",", ":"), ensure_ascii=False)).encode("utf-8")).hexdigest()
            self.last = rec["hash"]
            try:
                with open(self.path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            except OSError:
                logging.error("audit write failed (seq %s)", self.seq)
            self.recent.append(rec)
            return rec

    def verify(self) -> dict:
        """Recompute the chain from the file. Returns {ok, records, broken_at, head}."""
        if not self.path or not self.path.exists():
            return {"ok": True, "records": 0, "broken_at": None, "head": self.last}
        prev, n = GENESIS, 0
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            n += 1
            try:
                r = json.loads(line)
            except ValueError:
                return {"ok": False, "records": n, "broken_at": n, "reason": "unreadable line", "head": self.last}
            h = r.pop("hash", None)
            calc = hashlib.sha256((prev + json.dumps(r, sort_keys=True, separators=(",", ":"), ensure_ascii=False)).encode("utf-8")).hexdigest()
            if r.get("prev") != prev or h != calc:
                return {"ok": False, "records": n, "broken_at": r.get("seq", n), "reason": "hash chain mismatch (record edited, removed or inserted)", "head": self.last}
            prev = h
        return {"ok": prev == self.last, "records": n, "broken_at": None if prev == self.last else n + 1,
                "reason": None if prev == self.last else "records missing at the end of the file", "head": self.last}

    def tail(self, limit: int = 200, actor: str = "", action: str = "", q: str = "") -> list[dict]:
        rows = list(self.recent)
        if actor:
            rows = [r for r in rows if r["actor"] == actor]
        if action:
            rows = [r for r in rows if r["action"] == action]
        if q:
            ql = q.lower()[:80]
            rows = [r for r in rows if ql in json.dumps(r).lower()]
        return rows[-max(1, min(limit, 1000)):][::-1]


AUDIT = Audit()
