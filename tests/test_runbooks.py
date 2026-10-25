"""Every configured policy has a runbook, every register dependency exists, and the SIEM serves them safely."""
import re

from fastapi.testclient import TestClient

from app import catalog as K
from app import config as C
from app import runbooks as RB
from app.main import app

client = TestClient(app)
SECTIONS = ["When this fires", "First 10 minutes", "Is it real?", "Investigate", "Contain and recover", "Escalate",
            "False positives", "Close the case"]


def test_every_rule_has_exactly_one_runbook():
    owners = {}
    for rid, r in RB.load_all().items():
        for rule in r["rules"]:
            owners.setdefault(rule, []).append(rid)
    for rule in K.RULE_CATALOG:
        assert len(owners.get(rule, [])) == 1, f"{rule} needs exactly one runbook, has {owners.get(rule)}"


def test_runbook_depends_exist_in_register():
    for rid, r in RB.load_all().items():
        for k in r["depends"]:
            assert k in C.ENV_REGISTER, f"{rid} depends on unknown register entry {k}"


def test_runbook_structure_and_no_placeholders():
    for rid, r in RB.load_all().items():
        for s in SECTIONS:
            assert s in r["body"], f"{rid} lacks section {s}"
        assert not re.search(r"\b(TODO|TBD|XXX|lorem)\b", r["body"], re.I), rid
        assert r["owner"] and r["version"], rid


def test_runbook_rule_register_dependency_matches_register_used_by():
    """If the register says rule X reads entry K, X's runbook must list K, so the analyst sees what the rule assumes."""
    for k, m in C.ENV_REGISTER.items():
        used = m.get("used_by", [])
        for rule in re.findall(r"\b[DC]\d+\b", " ".join([used] if isinstance(used, str) else used)):
            rid = RB.for_rule(rule)
            assert rid and k in RB.load_all()[rid]["depends"], f"{rule} reads {k} but {rid} does not list it"


def test_api_index_and_detail():
    idx = client.get("/api/runbooks").json()
    assert len(idx) >= 15 and all("body" not in r for r in idx)
    d = client.get("/api/runbooks/RB-D5").json()
    assert d["generated"]["rules"][0]["id"] == "D5" and d["generated"]["register"]
    assert "APPROVED_LLM_HOSTS" in {x["key"] for x in d["generated"]["register"]}


def test_api_rejects_traversal_and_unknown():
    for bad in ("..%2F..%2Fetc%2Fpasswd", "RB-NOPE", "rb-d1", "RB-D1.md"):
        assert client.get(f"/api/runbooks/{bad}").status_code in (404, 422)


def test_runbook_shows_live_register_value():
    d = client.get("/api/runbooks/RB-D10").json()
    cidr = next(x for x in d["generated"]["register"] if x["key"] == "CORP_SOURCE_CIDRS")
    assert set(cidr["items"]) == {str(x) for x in C.CORP_SOURCE_CIDRS}
