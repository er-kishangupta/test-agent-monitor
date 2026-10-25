"""Editable retention and archive settings, under maker-checker.

config/platform.json is the baseline and changes by pull request. For the choices a Compliance owner makes day to day (how long to keep, which
tiers, where the archive lives) the dashboard can also change them, but never silently and never by one person:
  1. anyone proposes a change with a reason; the proposal is checked against the compliance checks R1-R10 and REFUSED if it would create a new failure
     (for example total retention below the regulatory minimum, tiers out of order, a region outside the permitted list, an http endpoint);
  2. a DIFFERENT, MORE SENIOR person approves; a change that weakens protection (shorter retention, shorter Object Lock, legal hold off, leaving S3,
     a new region, marking the policy confirmed) needs a LEAD;
  3. approval applies at once, and who, when, before and after go to the hash-chained audit log.
NOT editable here, by design: encryption and signing switches, the local path, keys, TLS, sign-in mode, the AI endpoint. They are deploy-time settings
(environment variables or pull request): a self-asserted person in a browser must not be able to switch protection off.
State = the proposal list (out/retention_proposals.json, or PLATFORM_STATE_DIR); approved proposals are replayed at start-up. In the demo the out folder
is memory-only, so changes are lost on restart: set PLATFORM_STATE_DIR to a mounted folder, or copy the effective settings into config/platform.json."""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

from . import retention
from .audit import AUDIT
from .register import ROLE_RANK, norm_actor

REGION_RX = re.compile(r"^[a-z0-9][a-z0-9-]{1,30}$")
BUCKET_RX = re.compile(r"^[a-z0-9][a-z0-9.-]{2,62}$")
KMS_RX = re.compile(r"^(|[A-Za-z0-9:/_.-]{1,200})$")
PREFIX_RX = re.compile(r"^[A-Za-z0-9._/-]{0,80}$")
TEXT_RX = re.compile(r"^[^\x00-\x1f\x7f]{1,160}$")

# path -> (label, type, constraint, help)
FIELDS: dict[str, dict] = {
    "regulatory_minimum_days": {"label": "Regulatory minimum (days)", "type": "int", "min": 1, "max": 36500, "group": "Retention periods", "help": "What the regulator and policy require at least. Compliance sets this."},
    "total_days": {"label": "Total retention (days)", "type": "int", "min": 1, "max": 36500, "group": "Retention periods", "help": "How long the archive keeps data. Must cover the regulatory minimum."},
    "immediate_access_days": {"label": "Immediate access (days)", "type": "int", "min": 1, "max": 3650, "group": "Retention periods", "help": "Recent data that must be searchable at once (PCI DSS: 3 months)."},
    "hot_days": {"label": "Hot tier (days)", "type": "int", "min": 1, "max": 3650, "group": "Retention periods", "help": "Fast, expensive search."},
    "warm_days": {"label": "Hot + warm (days)", "type": "int", "min": 1, "max": 36500, "group": "Retention periods", "help": "Age at which data moves to the cold archive."},
    "legal_hold": {"label": "Legal hold", "type": "bool", "group": "Policy", "help": "ON: nothing may expire."},
    "data_residency_regions": {"label": "Permitted regions (comma separated)", "type": "list", "group": "Policy", "help": "The archive may only live in these regions (UAE data residency)."},
    "status": {"label": "Policy status", "type": "enum", "choices": ["assumed", "confirmed"], "group": "Policy", "help": "assumed = placeholder until the owner confirms. Confirming needs a lead."},
    "owner": {"label": "Policy owner", "type": "text", "group": "Policy", "help": "Who answers for these numbers."},
    "archive.backend": {"label": "Archive storage", "type": "enum", "choices": ["local", "s3"], "group": "Archive storage", "help": "local = folder in the container (demo). s3 = S3 or an S3-compatible store with Object Lock (paid AWS service: needs approval)."},
    "archive.s3.endpoint_url": {"label": "S3 endpoint (blank = AWS)", "type": "url", "group": "Archive storage", "help": "Must be https. For a local MinIO test use an https endpoint."},
    "archive.s3.bucket": {"label": "Bucket", "type": "bucket", "group": "Archive storage", "help": ""},
    "archive.s3.region": {"label": "Region", "type": "region", "group": "Archive storage", "help": "Must be one of the permitted regions."},
    "archive.s3.prefix": {"label": "Key prefix", "type": "prefix", "group": "Archive storage", "help": ""},
    "archive.s3.object_lock_mode": {"label": "Object Lock mode", "type": "enum", "choices": ["COMPLIANCE", "GOVERNANCE"], "group": "Archive storage", "help": "COMPLIANCE cannot be shortened or removed by anyone, including the account owner."},
    "archive.s3.object_lock_days": {"label": "Object Lock (days)", "type": "int", "min": 1, "max": 36500, "group": "Archive storage", "help": "Must be at least the total retention."},
    "archive.s3.sse": {"label": "Server-side encryption", "type": "enum", "choices": ["aws:kms", "AES256"], "group": "Archive storage", "help": "aws:kms with a customer-managed key is the bank-grade choice."},
    "archive.s3.kms_key_id": {"label": "KMS key id or alias", "type": "kms", "group": "Archive storage", "help": "Key reference only. Never a secret."},
}
LOCKED = [("archive.encrypt", "Archive encryption (AES-256-GCM)"), ("archive.sign", "Archive signing (HMAC-SHA256)"), ("archive.local_path", "Local archive path"),
          ("ARCHIVE_ENC_KEY / ARCHIVE_HMAC_KEY", "Keys (secret manager or environment)"), ("TLS_CERT_FILE / TLS_KEY_FILE / REQUIRE_TLS", "TLS"),
          ("AUTH_MODE / TRUSTED_PROXY_CIDRS", "Sign-in mode"), ("AI_MODE / SOC_AI_ENDPOINTS", "AI assistant and its approved endpoint")]


class SettingsError(ValueError):
    def __init__(self, msg: str, code: int = 422):
        super().__init__(msg)
        self.code = code


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _get(cfg: dict, path: str):
    d = cfg.get("retention", {})
    for k in path.split("."):
        d = d.get(k, None) if isinstance(d, dict) else None
    return d


def coerce(path: str, raw):
    """Validate and normalise one submitted value. Raises SettingsError."""
    f = FIELDS.get(path)
    if f is None:
        raise SettingsError(f"'{path}' is not editable here: it is a deploy-time setting (environment variable or pull request)", 403)
    t = f["type"]
    try:
        if t == "int":
            if isinstance(raw, bool):
                raise ValueError
            v = int(str(raw).strip())
            if not f["min"] <= v <= f["max"]:
                raise SettingsError(f"{f['label']}: must be between {f['min']} and {f['max']}")
            return v
        if t == "bool":
            if isinstance(raw, bool):
                return raw
            if str(raw).strip().lower() in ("true", "1", "on", "yes"):
                return True
            if str(raw).strip().lower() in ("false", "0", "off", "no"):
                return False
            raise ValueError
        if t == "list":
            items = [x.strip().lower() for x in (raw if isinstance(raw, list) else str(raw).split(",")) if str(x).strip()]
            if not items or len(items) > 10 or not all(REGION_RX.match(x) for x in items):
                raise SettingsError(f"{f['label']}: one to ten region names such as me-central-1")
            return sorted(set(items))
        s = str(raw if raw is not None else "").strip()
        if t == "enum":
            if s not in f["choices"]:
                raise SettingsError(f"{f['label']}: must be one of {', '.join(f['choices'])}")
            return s
        rx = {"text": TEXT_RX, "bucket": BUCKET_RX, "region": REGION_RX, "prefix": PREFIX_RX, "kms": KMS_RX}.get(t)
        if t == "url":
            if s and not re.match(r"^https?://[A-Za-z0-9.:_/-]{3,200}$", s):
                raise SettingsError(f"{f['label']}: not a valid URL")
            return s
        if rx is not None and not rx.match(s):
            raise SettingsError(f"{f['label']}: not an acceptable value")
        return s
    except (ValueError, TypeError):
        raise SettingsError(f"{f['label']}: not a valid {t}")


def _failing(chk: list[dict]) -> set[str]:
    return {c["id"] for c in chk if c["status"] == "fail"}


def weakens(before: dict, after: dict) -> list[str]:
    """Why a change needs a lead: it reduces protection or confirms the policy."""
    why = []
    for p, label in (("total_days", "shorter total retention"), ("regulatory_minimum_days", "lower regulatory minimum"), ("archive.s3.object_lock_days", "shorter Object Lock")):
        b, a = before.get(p), after.get(p)
        if isinstance(b, int) and isinstance(a, int) and a < b:
            why.append(label)
    if before.get("legal_hold") is True and after.get("legal_hold") is False:
        why.append("legal hold switched off")
    if before.get("archive.backend") == "s3" and after.get("archive.backend") == "local":
        why.append("leaving S3 Object Lock")
    if set(after.get("data_residency_regions") or []) - set(before.get("data_residency_regions") or []):
        why.append("a new permitted region")
    if after.get("archive.s3.object_lock_mode") == "GOVERNANCE" and before.get("archive.s3.object_lock_mode") == "COMPLIANCE":
        why.append("Object Lock COMPLIANCE to GOVERNANCE")
    if before.get("status") != "confirmed" and after.get("status") == "confirmed":
        why.append("policy marked confirmed")
    return why


class RetentionSettings:
    def __init__(self, state_dir: Path | str, keys=None):
        d = Path(os.environ.get("PLATFORM_STATE_DIR") or state_dir)
        self.file = d / "retention_proposals.json"
        self.keys = keys
        self.proposals: list[dict] = []
        retention.OVERRIDE.clear()
        try:
            self.proposals = json.loads(self.file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
        for p in self.proposals:
            if p["status"] == "approved":
                retention.OVERRIDE.update(p["changes"])

    # ------------------------------------------------------------ read
    def current(self) -> dict:
        cfg = retention.load_platform()
        return {p: _get(cfg, p) for p in FIELDS}

    def view(self) -> dict:
        return {"values": self.current(), "baseline_file": "config/platform.json", "fields": [{"path": p, **f} for p, f in FIELDS.items()],
                "locked": [{"path": p, "label": l} for p, l in LOCKED], "proposals": self.proposals[::-1],
                "pending": sum(p["status"] == "pending" for p in self.proposals), "state_file": str(self.file),
                "effective": {"retention": retention.load_platform().get("retention", {})},
                "rules": ["A change is refused if it would create a new compliance failure (R1 to R10).",
                          "A different, more senior person approves. Weakening protection needs a lead.",
                          "Encryption, signing, keys, TLS, sign-in and the AI endpoint are deploy-time settings and cannot be changed here.",
                          "In the demo the state is memory-only: set PLATFORM_STATE_DIR to keep it, or copy the effective settings into config/platform.json by pull request."]}

    def _checks(self, overrides: dict) -> list[dict]:
        saved = dict(retention.OVERRIDE)
        try:
            retention.OVERRIDE.update(overrides)
            return retention.checks(retention.load_platform(), self.keys)
        finally:
            retention.OVERRIDE.clear()
            retention.OVERRIDE.update(saved)

    # ------------------------------------------------------------ maker
    def propose(self, actor: str, role: str, changes: dict, reason: str, ip: str = "") -> dict:
        actor, role = norm_actor(actor, role)
        if not isinstance(changes, dict) or not changes:
            raise SettingsError("no change submitted")
        if len(reason.strip()) < 10:
            raise SettingsError("say why (at least 10 characters)")
        now = self.current()
        clean = {}
        for path, raw in changes.items():
            v = coerce(path, raw)
            if v != now.get(path):
                clean[path] = v
        if not clean:
            raise SettingsError("nothing differs from the current settings", 409)
        before = self.current()
        after = {**before, **clean}
        cur_chk, new_chk = self._checks({}), self._checks(clean)
        new_fail = _failing(new_chk) - _failing(cur_chk)
        if new_fail:
            detail = "; ".join(f"{c['id']} {c['title']}: {c['detail']}" for c in new_chk if c["id"] in new_fail)
            AUDIT.log(actor, "retention_proposal_refused", ",".join(sorted(clean)), {"failing": sorted(new_fail)}, role, outcome="refused", ip=ip)
            raise SettingsError("refused, it would create a compliance failure: " + detail)
        needs_lead = weakens(before, after)
        p = {"id": f"RS-{len(self.proposals) + 1:03d}", "ts": _now(), "changes": clean, "before": {k: before[k] for k in clean}, "reason": reason.strip()[:300],
             "maker": actor, "maker_role": role, "status": "pending", "checker": None, "checker_role": None, "decided": None, "decision_note": None,
             "needs_lead": needs_lead, "impact": [{"id": a["id"], "from": b["status"], "to": a["status"]} for a, b in zip(new_chk, cur_chk) if a["status"] != b["status"]]}
        self.proposals.append(p)
        self._save()
        AUDIT.log(actor, "retention_proposed", p["id"], {"changes": clean, "needs_lead": needs_lead}, role, ip=ip)
        return p

    # ------------------------------------------------------------ checker
    def decide(self, pid: str, actor: str, role: str, decision: str, note: str | None, ip: str = "") -> dict:
        actor, role = norm_actor(actor, role)
        p = next((x for x in self.proposals if x["id"] == pid), None)
        if not p:
            raise SettingsError("proposal not found", 404)
        if p["status"] != "pending":
            raise SettingsError("already decided", 409)
        if decision not in ("approve", "reject"):
            raise SettingsError("decision must be approve or reject")
        problem = None
        if actor == p["maker"]:
            problem = "maker-checker: you cannot decide your own proposal"
        elif decision == "approve" and ROLE_RANK[role] <= ROLE_RANK[p["maker_role"]] and role != "lead":
            problem = f"maker-checker: approval needs a more senior role than the maker ({p['maker_role']})"
        elif decision == "approve" and p["needs_lead"] and role != "lead":
            problem = "this change weakens protection (" + ", ".join(p["needs_lead"]) + "): only a lead can approve it"
        if problem:
            AUDIT.log(actor, "retention_decision_refused", pid, {"decision": decision, "reason": problem}, role, outcome="refused", ip=ip)
            raise SettingsError(problem, 403)
        if decision == "approve":                                   # re-check: the settings may have moved since the proposal was made
            new_fail = _failing(self._checks(p["changes"])) - _failing(self._checks({}))
            if new_fail:
                raise SettingsError("no longer valid, it would now create a compliance failure: " + ", ".join(sorted(new_fail)), 409)
        p.update(status="approved" if decision == "approve" else "rejected", checker=actor, checker_role=role, decided=_now(), decision_note=(note or "")[:300] or None)
        if decision == "approve":
            retention.OVERRIDE.update(p["changes"])
        self._save()
        AUDIT.log(actor, f"retention_{p['status']}", pid, {"changes": p["changes"], "before": p["before"], "maker": p["maker"], "note": p["decision_note"]}, role, ip=ip)
        return p

    def _save(self) -> None:
        try:
            self.file.parent.mkdir(parents=True, exist_ok=True)
            self.file.write_text(json.dumps(self.proposals, indent=1), encoding="utf-8")
        except OSError:
            pass
