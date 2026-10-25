"""Held-out set: attacks and look-alikes written after the rules by a reviewer trying to get round them (see app/validation.py).
First pass before the fixes: 17 of 30 attacks caught. Now a regression set. The two accepted gaps must stay undetected on purpose: if one starts passing,
remove its gap flag so the scorecard stays honest."""
import pytest

from app.validation import HELDOUT, HELDOUT_FIRST_PASS, _evaluate, run_heldout


@pytest.mark.parametrize("c", HELDOUT, ids=lambda c: c.id)
def test_heldout_case(c):
    ok, got, _ = _evaluate(c)
    if c.gap:
        assert not ok, f"{c.title}: this accepted gap now passes; remove gap=True"
    else:
        assert ok, f"{c.title}: got {got}"


def test_heldout_summary_is_honest():
    r = run_heldout()
    assert r["false_alarms"] == 0
    assert r["attacks"] == HELDOUT_FIRST_PASS["attacks"] == 30
    assert HELDOUT_FIRST_PASS["detected"] == 17                     # the recorded first-pass result must not be rewritten
    assert {m["id"] for m in r["misses"] if not m["known_gap"]} == set()
    assert len([m for m in r["misses"] if m["known_gap"]]) == sum(c.gap for c in HELDOUT)
