"""Automated response. Everything here is a *simulation* of a SOAR/EDR action: it writes auditable
artefacts to OUT_DIR instead of calling real control planes. Swap each function for a real API call
(IdP token revoke, EDR network contain, GitHub branch protection, package-registry block) in production."""
from __future__ import annotations

import json
import logging
import re
import tempfile
import urllib.request
from pathlib import Path

from . import netpolicy
from .config import OUT_DIR, WEBHOOK_URL

SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


class Responder:
    def __init__(self, out_dir: Path | str | None = None):
        self.out = Path(out_dir or OUT_DIR)
        try:
            self.out.mkdir(parents=True, exist_ok=True)
            probe = self.out / ".write-test"
            probe.write_text("ok")
            probe.unlink()
        except OSError:
            self._fallback()

    def _fallback(self) -> None:
        """Degrade, never crash: e.g. non-root container + root-owned bind mount."""
        self.out = Path(tempfile.mkdtemp(prefix="agentmon_out_"))
        logging.warning("OUT_DIR not writable; responses are being written to %s instead (inside the container)", self.out)

    # file helpers ------------------------------------------------------------------------
    def _append(self, name: str, text: str) -> None:
        with open(self.out / name, "a", encoding="utf-8") as fh:
            fh.write(text if text.endswith("\n") else text + "\n")

    FILES = ("alerts.ndjson", "quarantine.log", "webhook_received.ndjson", "flagged_files.txt", "package_blocklist.txt", "approvals.log")

    def _truncate(self, name: str) -> None:
        p = self.out / name
        try:
            p.write_text("", encoding="utf-8")
        except PermissionError:
            p.unlink()                      # dir is writable but the file belongs to another user (e.g. root from an earlier run)
            p.write_text("", encoding="utf-8")

    def reset(self) -> None:
        try:
            for name in self.FILES:
                self._truncate(name)
        except OSError:
            self._fallback()
            for name in self.FILES:
                self._truncate(name)

    def record_approval(self, rec: dict) -> None:
        """Audit trail for human-in-the-loop decisions (approving executes the action; here it is simulated)."""
        self._append("approvals.log", json.dumps(rec, ensure_ascii=False))

    def write_alert(self, alert: dict) -> None:
        self._append("alerts.ndjson", json.dumps(alert, ensure_ascii=False))

    # policy ------------------------------------------------------------------------------
    def apply(self, alert: dict, session: dict) -> list[dict]:
        rank = SEV_RANK[alert["severity"]]
        actions: list[dict] = []
        if rank >= SEV_RANK["medium"]:
            actions.append(self._webhook(alert))
        if rank >= SEV_RANK["high"]:
            actions.append(self._quarantine_log(alert))
            if alert["evidence"].get("scope") == "host":
                actions.append(self._act("isolate_host_network", alert,
                                         f"EDR network containment requested for {alert['host']} (simulated)"))
            else:
                session["frozen"] = True
                actions.append(self._act("freeze_agent_session", alert,
                                         "Agent session suspended and short-lived tokens revoked (simulated)"))
            paths = alert["evidence"].get("paths") or []
            if paths:
                actions.append(self._flag_files(alert, paths))
            if alert["rule_id"] == "D3" and alert["evidence"].get("package"):
                self._append("package_blocklist.txt", alert["evidence"]["package"])
                actions.append(self._act("block_package", alert,
                                         f"{alert['evidence']['package']} added to registry blocklist"))
        return actions

    # actions -----------------------------------------------------------------------------
    def _act(self, name: str, alert: dict, detail: str) -> dict:
        return {"action": name, "status": "simulated", "detail": detail}

    def _quarantine_log(self, alert: dict) -> dict:
        rec = {
            "ts": alert["ts"], "alert_id": alert["alert_id"], "rule": alert["rule_id"],
            "severity": alert["severity"], "session": alert["session_id"], "user": alert["user"],
            "host": alert["host"], "reason": alert["title"],
        }
        self._append("quarantine.log", json.dumps(rec))
        return {"action": "write_quarantine_log", "status": "done", "detail": "out/quarantine.log"}

    def _flag_files(self, alert: dict, paths: list[str]) -> dict:
        for p in paths:
            clean = re.sub(r"[\x00-\x1f\x7f]", " ", str(p))[:300]   # no log-line injection via crafted file names
            self._append("flagged_files.txt", f"{alert['alert_id']}\t{alert['repo']}\t{clean}")
        return {"action": "flag_files", "status": "done", "detail": ", ".join(paths)}

    def _webhook(self, alert: dict) -> dict:
        payload = {
            "alert_id": alert["alert_id"], "severity": alert["severity"], "category": alert["category"],
            "title": alert["title"], "user": alert["user"], "host": alert["host"],
            "session": alert["session_id"], "recommended_action": alert["recommended_action"],
            "page_oncall": alert["severity"] in ("high", "critical"),
        }
        if WEBHOOK_URL.startswith("http") and not netpolicy.usable(WEBHOOK_URL, "Alert webhook"):
            self._append("webhook_received.ndjson", json.dumps(payload))
            return {"action": "notify_webhook", "status": "fallback", "detail": "webhook refused (" + netpolicy.check_url(WEBHOOK_URL, "Alert webhook")["detail"] + "); logged locally"}
        if WEBHOOK_URL.startswith("http"):
            try:
                req = urllib.request.Request(WEBHOOK_URL, data=json.dumps(payload).encode(),
                                             headers={"Content-Type": "application/json"})
                urllib.request.urlopen(req, timeout=3).read()
                return {"action": "notify_webhook", "status": "done", "detail": WEBHOOK_URL}
            except Exception as exc:  # network failure must never break detection
                self._append("webhook_received.ndjson", json.dumps(payload))
                return {"action": "notify_webhook", "status": "fallback", "detail": f"POST failed ({exc}); logged locally"}
        self._append("webhook_received.ndjson", json.dumps(payload))
        return {"action": "notify_webhook", "status": "done", "detail": "mock webhook -> out/webhook_received.ndjson"}
