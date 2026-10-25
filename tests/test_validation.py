"""The validation corpus is the contract: every attack variant must raise a case, no routine developer action may."""
import pytest

from app.validation import CASES, _evaluate, run_validation


@pytest.mark.parametrize("c", CASES, ids=lambda c: c.id)
def test_case(c):
    ok, got, _ = _evaluate(c)
    assert ok, f"{c.title}: got {got}"


def test_scorecard_totals():
    t = run_validation()["totals"]
    assert t["detected"] == t["attacks"] and t["false_alarms"] == 0 and t["attacks"] >= 150
