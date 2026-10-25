"""FastAPI service: ingest endpoint, alert/case/source APIs, mock webhook receiver, dashboard.

Security posture of the tool itself (see README "Securing the monitor"):
  * optional HTTP Basic auth for every route (DASHBOARD_USER / DASHBOARD_PASSWORD), constant-time compare
  * strict CSP + security headers, no inline script, no third-party assets
  * request-size limits, input validation, per-field truncation, bounded in-memory state
  * evidence is redacted before it is stored or displayed
"""
from __future__ import annotations

import asyncio
import base64
import hmac
import json
import logging
import os
import tempfile
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import authn
from . import config as C
from . import intel as INTEL
from . import netpolicy
from . import platform_view
from . import privacy
from . import retention as RET
from . import runbooks as RB
from .ai_assist import AIError, Assistant
from .audit import AUDIT
from .coverage import build as build_coverage
from .engine import STATUSES, Engine
from .register import Register, RegisterError, norm_actor
from .retention_settings import RetentionSettings, SettingsError
from .validation import run_validation

STATIC = Path(__file__).resolve().parent.parent / "static"
AUTH_USER = os.environ.get("DASHBOARD_USER", "analyst")
AUTH_PASS = os.environ.get("DASHBOARD_PASSWORD", "")
MAX_BODY = 5 * 1024 * 1024
SEC_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cache-Control": "no-store",
}

engine = Engine()
# Separate throw-away engine for the rule tester: nothing it processes touches the real alerts, cases or response files.
sandbox = Engine(tempfile.mkdtemp(prefix="agentmon_sbx_"))
sandbox.responder.apply = lambda alert, session: []
sandbox.responder.write_alert = lambda alert: None
sandbox.audit_enabled = False
register = Register(engine.responder.out)
intel_store = INTEL.IntelStore(engine.responder.out)
archive = RET.Archive(engine.responder.out)
ret_settings = RetentionSettings(engine.responder.out, archive.keys)
assistant = Assistant(engine.responder.out)
engine.enricher = lambda case, alerts, graph, sess: intel_store.enrich(INTEL.case_entities(case, alerts, graph, sess))
_auth_fail: dict[str, float] = {}
SSO_CFG = RET.load_platform().get("sso", {})


def who(request: Request) -> tuple[str, str, str]:
    """Actor, role, client address for the audit trail.
    AUTH_MODE=proxy: identity and role come from the identity-aware proxy (SSO); X-Actor / X-Role are ignored, so maker-checker runs on a real person.
    otherwise (PROTOTYPE): identity is self-asserted in X-Actor / X-Role; the optional shared password only keeps strangers out."""
    ip = request.client.host if request.client else ""
    ident = getattr(request.state, "identity", None)
    if ident is not None:
        return ident.actor, ident.role, ip
    actor, role = norm_actor(request.headers.get("x-actor"), request.headers.get("x-role"))
    return actor, role, ip
replay = {"running": False, "progress": 0, "total": 0, "task": None}


def load_sample() -> dict:
    engine.reset()
    with open(C.SAMPLE_FILE, encoding="utf-8") as fh:
        return engine.ingest_lines(fh)


async def watchdog():
    """Wall-clock silence detection for live ingestion (events posted to /api/ingest?live=true)."""
    while True:
        await asyncio.sleep(10)
        engine.tick(time.time())


@asynccontextmanager
async def lifespan(_: FastAPI):
    if not AUTH_PASS:
        logging.warning("DASHBOARD_PASSWORD is not set: the monitor is UNAUTHENTICATED. Keep it bound to localhost.")
    AUDIT.configure(engine.responder.out)
    if not intel_store.entries and os.environ.get("INTEL_SAMPLE", "1") != "0":
        try:
            r = intel_store.add_many(INTEL.parse(Path(C.SAMPLE_FILE).with_name("intel_sample.csv").read_text(encoding="utf-8")), "system", "sample list (synthetic)")
            AUDIT.log("system", "intel_loaded", "intel_sample.csv", {"added": r["added"]}, "system")
        except (OSError, INTEL.IntelError):
            pass
    register.check_expiry()
    load_sample()
    task = asyncio.create_task(watchdog())
    yield
    task.cancel()


app = FastAPI(title="Coding-Agent Threat Monitor", version="1.1", lifespan=lifespan,
              docs_url=None, redoc_url=None, openapi_url=None)


def _mode() -> str:
    m = os.environ.get("AUTH_MODE", "").strip().lower()
    return m if m in ("none", "basic", "proxy") else ("basic" if AUTH_PASS else "none")


def _scheme(request: Request) -> str:
    """https if this hop is TLS, or if a TRUSTED proxy says the client hop was (X-Forwarded-Proto is forgeable from anywhere else)."""
    ip = request.client.host if request.client else ""
    if request.url.scheme == "https":
        return "https"
    if os.environ.get("TLS_TERMINATED_UPSTREAM", "") == "1" and authn.from_trusted_proxy(ip):
        return request.headers.get("x-forwarded-proto", "http").split(",")[0].strip().lower()
    return "http"


@app.middleware("http")
async def guard(request: Request, call_next):
    mode = _mode()
    scheme = _scheme(request)
    tls_on = netpolicy.tls_status()
    if tls_on["require_tls"] and scheme != "https" and request.url.path != "/healthz":
        return Response(status_code=421, content="HTTPS required", headers=SEC_HEADERS)       # nothing travels in plain text when REQUIRE_TLS=1
    if request.url.path != "/healthz":
        if mode == "basic" and AUTH_PASS:
            ok = False
            header = request.headers.get("authorization", "")
            if header.startswith("Basic "):
                try:
                    user, _, pw = base64.b64decode(header[6:]).decode("utf-8").partition(":")
                    ok = hmac.compare_digest(user.encode(), AUTH_USER.encode()) and hmac.compare_digest(pw.encode(), AUTH_PASS.encode())
                except Exception:
                    ok = False
            if not ok:
                ip = request.client.host if request.client else ""
                if time.time() - _auth_fail.get(ip, 0) > 60:               # one record per client per minute: a password spray must not flood the log
                    _auth_fail[ip] = time.time()
                    AUDIT.log("unauthenticated", "auth_failed", request.url.path, {"method": request.method}, outcome="denied", ip=ip)
                return Response(status_code=401, headers={**SEC_HEADERS, "WWW-Authenticate": 'Basic realm="agent-monitor"'})
        elif mode == "proxy":
            ip = request.client.host if request.client else ""
            ident, why = authn.identify_proxy(request.headers, ip, SSO_CFG)
            if ident is None:
                if time.time() - _auth_fail.get(ip, 0) > 60:
                    _auth_fail[ip] = time.time()
                    AUDIT.log("unauthenticated", "sso_denied", request.url.path, {"method": request.method, "reason": why}, outcome="denied", ip=ip)
                return Response(status_code=403, content="Access denied", headers=SEC_HEADERS)
            request.state.identity = ident
    resp = await call_next(request)
    for k, v in SEC_HEADERS.items():
        resp.headers[k] = v
    if scheme == "https" or tls_on["serving_tls"]:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp


app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.get("/")
def dashboard():
    return FileResponse(STATIC / "index.html")


@app.get("/healthz")
def healthz():
    return {"ok": True}


# ---------------------------------------------------------------------------------- read APIs
@app.get("/api/stats")
def stats():
    return {**engine.stats(), "replay": {k: replay[k] for k in ("running", "progress", "total")},
            "ingest_mode": "live" if engine.live else "stream"}


@app.get("/api/alerts")
def alerts(severity: str | None = None, category: str | None = None, status: str | None = None,
           q: str | None = None, limit: int = 500, tier: Literal["case", "signal", "all"] = "case"):
    """Default view is what an analyst must read: alerts that opened or joined a case. Low-severity signals are stored and
    searchable (tier=signal or all) but never page anyone."""
    rows = engine.alerts if tier == "all" else [a for a in engine.alerts if a.get("tier", "case") == tier]
    if severity:
        rows = [a for a in rows if a["severity"] == severity]
    if category:
        rows = [a for a in rows if a["category"] == category]
    if status:
        rows = [a for a in rows if a["status"] == status]
    if q:
        ql = q.lower()[:100]
        rows = [a for a in rows if ql in json.dumps(a).lower()]
    return sorted(rows, key=lambda a: a["ts"], reverse=True)[: max(1, min(limit, 1000))]


@app.get("/api/cases")
def cases():
    order = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
    rows = [engine.case_view(c) for c in engine.cases.values()]
    return sorted(rows, key=lambda c: (c["status"] in ("closed_tp", "closed_fp"), order[c["priority"]["level"]], -c["priority"]["score"], c["updated"]))


@app.get("/api/cases/{case_id}")
def case(case_id: str):
    c = next((c for c in engine.cases.values() if c["case_id"] == case_id), None)
    if not c:
        raise HTTPException(404, "case not found")
    return engine.case_view(c, detail=True)


class CaseUpdate(BaseModel):
    status: Literal["new", "triaged", "investigating", "contained", "closed_tp", "closed_fp"] | None = None
    owner: str | None = Field(default=None, max_length=64)
    note: str | None = Field(default=None, max_length=1000)


def guard_text(actor: str, role: str, ip: str, target: str, *texts: str | None) -> None:
    """Refuse card data / sensitive identifiers typed into free-text fields (CBUAE privacy). The value is never echoed or logged, only its type."""
    if privacy.mode() == "off":
        return
    found = privacy.scan(*texts)
    if found:
        AUDIT.log(actor, "privacy_text_refused", target, {"types": found}, role, outcome="denied", ip=ip)
        raise HTTPException(422, "Not saved: the text looks like it contains " + ", ".join(found) + ". Remove it and refer to the case or alert ID instead (privacy rule: no card data or sensitive customer data in notes).")


@app.get("/api/privacy-notice")
def privacy_notice():
    """The banner text shown in case management and the register forms; one source for the page and the tests."""
    return privacy.notice()


class Decision(BaseModel):
    key: str = Field(max_length=40)
    decision: Literal["approved", "declined"]
    note: str | None = Field(default=None, max_length=300)


@app.post("/api/cases/{case_id}/decisions")
def decide(case_id: str, body: Decision, request: Request):
    actor, role, ip = who(request)
    guard_text(actor, role, ip, case_id, body.note)
    try:
        c = engine.decide(case_id, body.key, body.decision, actor=actor, note=body.note)
        AUDIT.log(actor, "case_decision", case_id, {"decision_key": body.key, "decision": body.decision, "note_chars": len(body.note or "")}, role, ip=ip)
    except ValueError:
        raise HTTPException(422, "unknown decision for this case")
    if not c:
        raise HTTPException(404, "case not found")
    return engine.case_view(c, detail=True)


@app.patch("/api/cases/{case_id}")
def update_case(case_id: str, body: CaseUpdate, request: Request):
    actor, role, ip = who(request)
    guard_text(actor, role, ip, case_id, body.note, body.owner)
    c = engine.update_case(case_id, body.status, body.owner, body.note, actor=actor)
    if not c:
        raise HTTPException(404, "case not found")
    AUDIT.log(actor, "case_updated", case_id, {"status": body.status, "owner": body.owner, "note_chars": len(body.note or "")}, role, ip=ip)
    return engine.case_view(c, detail=True)


@app.get("/api/sources")
def sources():
    return engine.sources_view()


@app.get("/api/pipeline")
def pipeline():
    return engine.pipeline_view()


@app.get("/api/statuses")
def statuses():
    return STATUSES


@app.get("/api/responses")
def responses():
    def tail(name, n=40):
        p = engine.responder.out / name
        if not p.exists():
            return []
        return [l for l in p.read_text(encoding="utf-8").splitlines() if l.strip()][-n:]
    return {"quarantine_log": tail("quarantine.log"), "webhook_received": tail("webhook_received.ndjson"),
            "flagged_files": tail("flagged_files.txt"), "package_blocklist": tail("package_blocklist.txt")}


@app.get("/api/environment")
def environment():
    """The known-environment register that the policies read: what is 'normal here', who owns each fact, whether it is confirmed, what is proposed."""
    return register.view()


class Proposal(BaseModel):
    key: str = Field(max_length=60)
    op: Literal["add", "remove", "set", "confirm"]
    value: str | None = Field(default=None, max_length=200)
    reason: str = Field(max_length=300)
    case_id: str | None = Field(default=None, max_length=20)


class ProposalDecision(BaseModel):
    decision: Literal["approve", "reject"]
    note: str | None = Field(default=None, max_length=300)


@app.post("/api/environment/proposals")
def propose(body: Proposal, request: Request):
    """Maker step: propose a change to the register (usually after closing a case as a false positive). Nothing changes until a checker approves."""
    actor, role, ip = who(request)
    guard_text(actor, role, ip, body.key, body.value, body.reason)
    try:
        return register.propose(actor, role, body.key, body.op, body.value, body.reason, body.case_id, ip)
    except RegisterError as e:
        raise HTTPException(e.code, str(e))


@app.post("/api/environment/proposals/{pid}/decision")
def decide_proposal(pid: str, body: ProposalDecision, request: Request):
    """Checker step: a different, more senior person approves or rejects. Approval changes the live policies immediately."""
    actor, role, ip = who(request)
    guard_text(actor, role, ip, pid, body.note)
    try:
        return register.decide(pid, actor, role, body.decision, body.note, ip)
    except RegisterError as e:
        raise HTTPException(e.code, str(e))


class RetentionProposal(BaseModel):
    changes: dict[str, str | int | bool | list[str]]
    reason: str = Field(min_length=10, max_length=300)


@app.get("/api/platform/retention")
def retention_settings_view():
    """Editable retention and archive settings, the proposals, and what stays deploy-time only."""
    return ret_settings.view()


@app.post("/api/platform/retention/proposals")
def retention_propose(body: RetentionProposal, request: Request):
    """Maker step: propose new retention or archive settings. Refused if it would create a compliance failure; takes effect only when a checker approves."""
    actor, role, ip = who(request)
    guard_text(actor, role, ip, "retention", body.reason)
    try:
        return ret_settings.propose(actor, role, body.changes, body.reason, ip)
    except SettingsError as e:
        raise HTTPException(e.code, str(e))


@app.post("/api/platform/retention/proposals/{pid}/decision")
def retention_decide(pid: str, body: ProposalDecision, request: Request):
    """Checker step: a different, more senior person (a lead, if the change weakens protection) approves or rejects."""
    actor, role, ip = who(request)
    guard_text(actor, role, ip, pid, body.note)
    try:
        return ret_settings.decide(pid, actor, role, body.decision, body.note, ip)
    except SettingsError as e:
        raise HTTPException(e.code, str(e))


@app.get("/api/audit")
def audit_log(limit: int = 200, actor: str = "", action: str = "", q: str = ""):
    return {"records": AUDIT.tail(limit, actor, action, q), "total": AUDIT.seq, "head": AUDIT.last, "file": "out/audit.ndjson"}


@app.get("/api/audit/verify")
def audit_verify():
    return AUDIT.verify()


_VALIDATION = None


@app.get("/api/validation")
def validation():
    """Precision / recall scorecard from the labelled detection corpus (app/validation.py). The corpus is static, so it is computed once."""
    global _VALIDATION
    if _VALIDATION is None:
        _VALIDATION = run_validation()
    return _VALIDATION


@app.get("/api/runbooks")
def runbooks():
    """Index of runbooks, one per configured policy (plus triage and register review)."""
    return RB.index()


@app.get("/api/runbooks/{rid}")
def runbook(rid: str):
    """One runbook: the written procedure, plus a section generated from the live catalog and the live register values."""
    r = RB.get(rid)
    if not r:
        raise HTTPException(404, "no such runbook")
    return r


@app.get("/api/whoami")
def whoami(request: Request):
    actor, role, _ = who(request)
    return {"mode": _mode(), "actor": actor, "role": role, "from_sso": getattr(request.state, "identity", None) is not None,
            "note": "Identity comes from the identity-aware proxy." if getattr(request.state, "identity", None) is not None else "Identity is typed in the page: self-asserted in this mode."}


@app.get("/api/coverage")
def coverage():
    """MITRE ATT&CK / ATLAS coverage computed from the rule catalog, with the validation corpus as evidence per rule."""
    return build_coverage(validation())


@app.get("/api/rules")
def rules():
    return engine.rules_view()


# ---------------------------------------------------------------------------------- intel and enrichment list
@app.get("/api/intel")
def intel_list():
    return intel_store.view()


@app.post("/api/intel")
async def intel_upload(request: Request, label: str = ""):
    """Body: CSV with a header row, or a JSON list of objects (see app/intel.py). Enrichment only: nothing here changes a detection."""
    actor, role, ip = who(request)
    if int(request.headers.get("content-length", 0) or 0) > INTEL.MAX_BYTES:
        raise HTTPException(413, "upload too large (max 1 MB)")
    body = await request.body()
    if len(body) > INTEL.MAX_BYTES:
        raise HTTPException(413, "upload too large (max 1 MB)")
    try:
        res = intel_store.add_many(INTEL.parse(body.decode("utf-8", "replace")), actor, label)
    except INTEL.IntelError as e:
        AUDIT.log(actor, "intel_upload", "intel_list", {"error": str(e), "bytes": len(body)}, role, outcome="refused", ip=ip)
        raise HTTPException(422, str(e))
    AUDIT.log(actor, "intel_upload", "intel_list", {"added": res["added"], "updated": res["updated"], "rejected": res["rejected_count"], "bytes": len(body), "label": label[:60]}, role, ip=ip)
    return res


@app.delete("/api/intel/{eid}")
def intel_delete(eid: str, request: Request):
    actor, role, ip = who(request)
    e = intel_store.remove(eid)
    if not e:
        raise HTTPException(404, "no such row")
    AUDIT.log(actor, "intel_removed", eid, {"type": e["type"], "value": e["value"], "kind": e["kind"]}, role, ip=ip)
    return {"removed": eid}


@app.post("/api/intel/hunt")
def intel_hunt(request: Request):
    actor, role, ip = who(request)
    res = INTEL.retro_hunt(intel_store, engine)
    AUDIT.log(actor, "intel_retro_hunt", "intel_list", {"rows": res["rows_searched"], "hits": res["hit_total"]}, role, ip=ip)
    return res


# ---------------------------------------------------------------------------------- platform, retention, AI
@app.get("/api/platform")
def platform(request: Request):
    """Sign-in, TLS, retention, integrity, AI and governance checks, plus the written list of what was considered, built, optional or left out."""
    return platform_view.build(engine, register, intel_store, archive, assistant, AUDIT, _scheme(request), _mode())


@app.post("/api/retention/archive")
def retention_archive(request: Request):
    """Write new alerts, audit records and case snapshots to the archive: compressed, encrypted, signed and chained. Refuses to write plain text."""
    actor, role, ip = who(request)
    try:
        res = archive.archive_now(engine.alerts, list(AUDIT.recent), [engine.case_view(c) for c in engine.cases.values()])
    except RET.ArchiveError as e:
        AUDIT.log(actor, "archive_run", "archive", {"error": str(e)}, role, outcome="refused", ip=ip)
        raise HTTPException(409, str(e))
    AUDIT.log(actor, "archive_run", "archive", {"batches": len(res["batches"]), "records": sum(b["records"] for b in res["batches"])}, role, ip=ip)
    return res


@app.get("/api/retention/verify")
def retention_verify():
    return archive.verify()


@app.get("/api/ai/status")
def ai_status():
    return assistant.status()


@app.post("/api/ai/kill")
def ai_kill(request: Request):
    """Kill switch: anyone can switch the assistant off (the safe direction). Only a restart re-arms it."""
    actor, role, ip = who(request)
    assistant.kill()
    AUDIT.log(actor, "ai_kill_switch", "ai_assistant", {}, role, ip=ip)
    return assistant.status()


@app.post("/api/cases/{case_id}/ai-review")
def ai_review(case_id: str, request: Request):
    """Ask the optional AI assistant for a second opinion. Advice only: stored beside the case, never read by detection, priority or response."""
    actor, role, ip = who(request)
    c = next((c for c in engine.cases.values() if c["case_id"] == case_id), None)
    if not c:
        raise HTTPException(404, "case not found")
    try:
        rec = assistant.review(engine.case_view(c, detail=True), actor, role, AUDIT)
    except AIError as e:
        raise HTTPException(e.code, str(e))
    engine.ai_reviews.setdefault(case_id, []).append(rec)
    del engine.ai_reviews[case_id][:-5]
    return rec


@app.get("/api/cases/{case_id}/ai-preview")
def ai_preview(case_id: str, request: Request):
    """Show exactly what the AI assistant would receive for this case under the current data policy. Nothing is sent."""
    actor, role, ip = who(request)
    c = next((c for c in engine.cases.values() if c["case_id"] == case_id), None)
    if not c:
        raise HTTPException(404, "case not found")
    return assistant.preview(engine.case_view(c, detail=True), actor, role, AUDIT)


# ---------------------------------------------------------------------------------- write APIs
@app.post("/api/test-event")
async def test_event(request: Request):
    actor, role, ip = who(request)
    """Rule tester: run up to 50 NDJSON events through the rules in a throw-away engine and show what fires. Nothing is stored."""
    body = await request.body()
    if len(body) > 64 * 1024:
        raise HTTPException(413, "payload too large (max 64 KB for the rule tester)")
    lines = [l for l in body.decode("utf-8", "replace").splitlines() if l.strip()][:50]
    sandbox.reset()
    res = sandbox.ingest_lines(lines)
    alerts = [{"rule_id": a["rule_id"], "severity": a["severity"], "title": a["title"], "signals": a["evidence"].get("signals", []),
               "snippet": a["evidence"].get("snippet", ""), "mitre": [t["id"] for k in ("attack", "atlas") for t in a["mitre"][k]],
               "recommended_action": a["recommended_action"]} for a in sandbox.alerts]
    AUDIT.log(actor, "rule_test", "sandbox", {"events": res["ingested"], "rejected": res["rejected"], "alerts": len(alerts)}, role, ip=ip)
    return {"events_accepted": res["ingested"], "rejected": res["rejected"], "alerts": alerts}



@app.post("/api/ingest")
async def ingest(request: Request, live: bool = False):
    """Body: NDJSON, one event per line (max 5 MB). live=true arms the wall-clock silence watchdog."""
    if int(request.headers.get("content-length", 0) or 0) > MAX_BODY:
        raise HTTPException(413, "payload too large (max 5 MB per request)")
    body = await request.body()
    if len(body) > MAX_BODY:
        raise HTTPException(413, "payload too large (max 5 MB per request)")
    if live:
        engine.live = True
    actor, role, ip = who(request)
    res = engine.ingest_lines(body.decode("utf-8", "replace").splitlines())
    AUDIT.log(actor, "ingest", "api", {"events": res["ingested"], "rejected": res["rejected"], "bytes": len(body), "live": live}, role, ip=ip)
    return res


@app.post("/api/reset")
def reset(request: Request):
    actor, role, ip = who(request)
    AUDIT.log(actor, "reset", "engine", {"alerts_cleared": len(engine.alerts), "cases_cleared": len(engine.cases)}, role, ip=ip)
    replay["running"] = False
    engine.reset()
    return {"ok": True}


@app.post("/api/load-sample")
def reload_sample(request: Request):
    actor, role, ip = who(request)
    replay["running"] = False
    res = load_sample()
    AUDIT.log(actor, "load_sample", "engine", {"events": res["ingested"]}, role, ip=ip)
    return res


@app.post("/api/replay")
async def start_replay(request: Request, rate: int = 150):
    actor, role, ip = who(request)
    AUDIT.log(actor, "replay_started", "engine", {"rate": rate}, role, ip=ip)
    """Animated replay of the sample file so the dashboard fills up live (rate = events/second)."""
    if replay["task"] and not replay["task"].done():
        replay["running"] = False
        await asyncio.sleep(0.05)
    with open(C.SAMPLE_FILE, encoding="utf-8") as fh:
        events = sorted((json.loads(l) for l in fh if l.strip()), key=lambda e: e["ts"])
    engine.reset()
    replay.update(running=True, progress=0, total=len(events))
    engine.metrics["lines_received"] = 0

    async def run():
        for i, ev in enumerate(events, 1):
            if not replay["running"]:
                return
            engine.metrics["lines_received"] += 1
            engine.safe_process(ev)
            replay["progress"] = i
            if i % 5 == 0:
                await asyncio.sleep(5 / max(min(rate, 5000), 1))
        replay["running"] = False

    replay["task"] = asyncio.create_task(run())
    return {"started": True, "events": len(events)}


@app.post("/mock/webhook")
async def mock_webhook(request: Request):
    """Stand-in receiver for an external SOAR/Slack-style webhook (for use from another service or curl)."""
    body = await request.body()
    if len(body) > 64 * 1024:
        raise HTTPException(413, "payload too large")
    try:
        payload = json.loads(body)
    except ValueError:
        raise HTTPException(400, "invalid JSON")
    with open(engine.responder.out / "webhook_received.ndjson", "a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload) + "\n")
    return JSONResponse({"received": True})
