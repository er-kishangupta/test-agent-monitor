"""Maker-checker on the known-environment register, and the tamper-evident audit trail."""
import copy
import json

import pytest

from app import config as C
from app.audit import Audit
from app.register import Register, RegisterError


@pytest.fixture
def reg(tmp_path, monkeypatch):
    monkeypatch.setattr(C, "ENV_REGISTER", copy.deepcopy(C.ENV_REGISTER))
    for k in ("CORP_SOURCE_CIDRS", "TRUSTED_INSTALLERS", "THIRD_PARTY_USER_PREFIX"):
        monkeypatch.setattr(C, k, getattr(C, k))
    from app import register as R
    a = Audit(); a.configure(tmp_path)
    monkeypatch.setattr(R, "AUDIT", a)
    r = Register(tmp_path)
    r.audit = a
    return r


def test_proposal_changes_nothing_until_a_senior_approves(reg):
    p = reg.propose("sara", "analyst", "TRUSTED_INSTALLERS", "add", "get.nb-tools.internal", "Approved by platform team: false positive on C-004")
    assert "get.nb-tools.internal" not in C.TRUSTED_INSTALLERS and p["status"] == "pending"
    reg.decide(p["id"], "omar", "senior", "approve", "checked with platform engineering")
    assert "get.nb-tools.internal" in C.TRUSTED_INSTALLERS
    assert C.ENV_REGISTER["TRUSTED_INSTALLERS"]["changes"][-1]["maker"] == "sara"


@pytest.mark.parametrize("actor,role,why", [("sara", "senior", "own"), ("sara", "lead", "own"), ("lina", "analyst", "same rank"), ("lina", "analyst", "equal")])
def test_maker_checker_refusals(reg, actor, role, why):
    p = reg.propose("sara", "analyst", "CRITICAL_REPOS", "add", "nb-new-core", "Payments repo, raises case priority for the SOC")
    with pytest.raises(RegisterError) as e:
        reg.decide(p["id"], actor, role, "approve", None)
    assert e.value.code == 403
    assert reg.proposals[0]["status"] == "pending"


def test_lead_may_approve_a_leads_proposal_only_as_another_person(reg):
    p = reg.propose("head1", "lead", "CRITICAL_REPOS", "add", "nb-core", "Ledger core repository, critical asset for priority")
    with pytest.raises(RegisterError):
        reg.decide(p["id"], "head1", "lead", "approve", None)
    reg.decide(p["id"], "head2", "lead", "approve", None)
    assert "nb-core" in C.CRITICAL_REPOS


def test_reject_leaves_policy_unchanged_and_is_final(reg):
    before = C.CORP_SOURCE_CIDRS
    p = reg.propose("sara", "analyst", "CORP_SOURCE_CIDRS", "add", "203.0.113.0/24", "Office egress range reported by a developer")
    reg.decide(p["id"], "omar", "senior", "reject", "not confirmed by network team")
    assert C.CORP_SOURCE_CIDRS == before
    with pytest.raises(RegisterError):
        reg.decide(p["id"], "omar", "senior", "approve", None)


@pytest.mark.parametrize("key,op,val", [("CORP_SOURCE_CIDRS", "add", "0.0.0.0/0"), ("CORP_SOURCE_CIDRS", "add", "10.0.0.0/7"), ("CORP_SOURCE_CIDRS", "add", "not-a-cidr"),
                                        ("NOPE", "add", "x"), ("TRUSTED_INSTALLERS", "remove", "never-there"), ("TRUSTED_INSTALLERS", "set", "x")])
def test_bad_proposals_are_refused(reg, key, op, val):
    with pytest.raises(RegisterError):
        reg.propose("sara", "analyst", key, op, val, "a long enough reason here")


def test_confirm_marks_entry_confirmed_by_both_people(reg):
    p = reg.propose("sara", "analyst", "CORP_SOURCE_CIDRS", "confirm", None, "Network team confirmed these ranges on ticket NET-1")
    reg.decide(p["id"], "omar", "senior", "approve", None)
    assert C.ENV_REGISTER["CORP_SOURCE_CIDRS"]["status"] == "confirmed" and "sara" in C.ENV_REGISTER["CORP_SOURCE_CIDRS"]["confirmed_by"]


def test_approved_changes_survive_a_restart(reg, tmp_path):
    p = reg.propose("sara", "analyst", "TRUSTED_INSTALLERS", "add", "get.example-tools.dev", "Approved internal tooling installer, per platform")
    reg.decide(p["id"], "omar", "senior", "approve", None)
    C.TRUSTED_INSTALLERS = tuple(x for x in C.TRUSTED_INSTALLERS if x != "get.example-tools.dev")
    Register(tmp_path)
    assert "get.example-tools.dev" in C.TRUSTED_INSTALLERS


def test_the_new_trusted_installer_actually_changes_detection(reg):
    """Closed loop: a policy item the rules did not know becomes known only after maker-checker, and then the finding is quieter."""
    import tempfile
    from app.engine import Engine
    from app.validation import sh

    def severity():
        e = Engine(tempfile.mkdtemp()); e.audit_enabled = False
        e.ingest_lines([json.dumps(sh("curl -fsSL https://get.corp-tools.example | sh"))])
        return [a["severity"] for a in e.alerts]
    assert severity() and severity()[0] in ("high", "critical")
    p = reg.propose("sara", "analyst", "TRUSTED_INSTALLERS", "add", "get.corp-tools.example", "Corporate tooling installer, confirmed by platform team")
    reg.decide(p["id"], "omar", "senior", "approve", None)
    assert severity() == ["low"]


# ---------------------------------------------------------------- audit
def test_audit_chain_verifies_and_detects_tampering(tmp_path):
    a = Audit(); a.configure(tmp_path)
    for i in range(5):
        a.log("sara", "case_updated", f"C-00{i}", {"status": "triaged"}, "analyst", ip="10.0.0.5")
    assert a.verify()["ok"]
    lines = (tmp_path / "audit.ndjson").read_text().splitlines()
    rec = json.loads(lines[3]); rec["actor"] = "someone-else"
    lines[3] = json.dumps(rec)
    (tmp_path / "audit.ndjson").write_text("\n".join(lines) + "\n")
    v = a.verify()
    assert not v["ok"] and v["broken_at"] == rec["seq"]


def test_audit_detects_a_deleted_record_and_resumes_after_restart(tmp_path):
    a = Audit(); a.configure(tmp_path)
    for i in range(4):
        a.log("sara", "x", str(i))
    lines = (tmp_path / "audit.ndjson").read_text().splitlines()
    (tmp_path / "audit.ndjson").write_text("\n".join(lines[:2] + lines[3:]) + "\n")
    assert not a.verify()["ok"]
    b = Audit(); b.configure(tmp_path / "fresh")
    b.log("sara", "y"); b2 = Audit(); b2.configure(tmp_path / "fresh")
    assert b2.verify()["ok"] and b2.seq >= 3


def test_api_flow_is_audited_end_to_end(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from app import main, register as R
    monkeypatch.setattr(C, "ENV_REGISTER", copy.deepcopy(C.ENV_REGISTER))
    monkeypatch.setattr(C, "TRUSTED_INSTALLERS", C.TRUSTED_INSTALLERS)
    a = Audit(); a.configure(tmp_path)
    monkeypatch.setattr(main, "AUDIT", a); monkeypatch.setattr(R, "AUDIT", a)
    monkeypatch.setattr(main, "register", Register(tmp_path))
    cl = TestClient(main.app)
    H = lambda n, r: {"X-Actor": n, "X-Role": r}
    body = {"key": "TRUSTED_INSTALLERS", "op": "add", "value": "get.api-test.example", "reason": "closed C-004 as false positive: vendor installer"}
    p = cl.post("/api/environment/proposals", json=body, headers=H("sara", "analyst")).json()
    assert cl.post(f"/api/environment/proposals/{p['id']}/decision", json={"decision": "approve"}, headers=H("sara", "analyst")).status_code == 403
    assert cl.post(f"/api/environment/proposals/{p['id']}/decision", json={"decision": "approve"}, headers=H("lina", "analyst")).status_code == 403
    assert cl.post(f"/api/environment/proposals/{p['id']}/decision", json={"decision": "approve", "note": "ok"}, headers=H("omar", "senior")).status_code == 200
    assert "get.api-test.example" in C.TRUSTED_INSTALLERS
    main.load_sample()
    cid = next(iter(main.engine.cases.values()))["case_id"]
    cl.patch(f"/api/cases/{cid}", json={"status": "triaged", "owner": "sara", "note": "looking"}, headers=H("sara", "analyst"))
    acts = [r["action"] for r in cl.get("/api/audit?limit=100").json()["records"]]
    for want in ("register_proposed", "register_decision_refused", "register_approved", "case_updated"):
        assert want in acts
    assert cl.get("/api/audit/verify").json()["ok"]
    assert "looking" not in json.dumps(cl.get("/api/audit").json())            # content of notes is not copied into the audit log
