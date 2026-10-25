"""CLI dashboard:  python -m app.cli [--file data/sample_events.ndjson] [--min-severity medium] [--category D4]
Runs the same engine as the web service and prints counts, the alert feed and an evaluation vs ground truth."""
from __future__ import annotations

import argparse
import json
import tempfile

from . import config as C
from .engine import Engine

COL = {"critical": "\033[1;41m", "high": "\033[1;31m", "medium": "\033[33m", "low": "\033[36m"}
RST = "\033[0m"
RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def evaluate(engine: Engine) -> list[str]:
    try:
        gt = json.load(open(C.GROUND_TRUTH_FILE, encoding="utf-8"))
    except FileNotFoundError:
        return []
    by_sess: dict[str, set] = {}
    for a in engine.alerts:
        if a["tier"] == "case":                       # low-severity signals are stored but are not alerts a human must read
            by_sess.setdefault(a["session_id"], set()).add(a["rule_id"])
    lines, hit = [], 0
    for sc in gt["attack_scenarios"]:
        got = by_sess.get(sc["session_id"], set())
        ok = set(sc["expected_rules"]) <= got
        hit += ok
        lines.append(f"  {'PASS' if ok else 'MISS'}  {sc['scenario']:<58} expected {sc['expected_rules']} got {sorted(got)}")
    fp = [s for s in gt["benign_sessions"] if s in by_sess]
    lines.append(f"  Detection: {hit}/{len(gt['attack_scenarios'])} scenarios | False positives: {len(fp)}/{len(gt['benign_sessions'])} benign sessions opened a case")
    return lines


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", default=str(C.SAMPLE_FILE))
    ap.add_argument("--min-severity", default="low", choices=list(RANK))
    ap.add_argument("--category")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--signals", action="store_true", help="also list low-severity signals (stored, never paged)")
    ap.add_argument("--out-dir", default=None, help="where responses are written (default: temp dir)")
    args = ap.parse_args()

    eng = Engine(args.out_dir or tempfile.mkdtemp(prefix="agentmon_"))
    with open(args.file, encoding="utf-8") as fh:
        res = eng.ingest_lines(fh)
    st = eng.stats()
    col = (lambda s, t: t) if args.no_color else (lambda s, t: f"{COL[s]}{t}{RST}")

    print(f"\n== Coding-Agent Threat Monitor == {res['ingested']} events ingested, {res['rejected']} rejected")
    print(f"Active alerts: {st['alerts_open']}   Frozen agent sessions: {st['frozen_sessions']}   Hosts monitored: {st['hosts_monitored']}")
    print("By severity: " + "  ".join(f"{k}={v}" for k, v in st["by_severity"].items()))
    print("By category:")
    for k, v in sorted(st["by_category"].items(), key=lambda kv: -kv[1]):
        print(f"  {k:<26} {'█' * v} {v}")
    print("\nAlert feed (newest first):")
    for a in sorted(eng.alerts, key=lambda x: x["ts"], reverse=True):
        if RANK[a["severity"]] < RANK[args.min_severity] or (a["tier"] == "signal" and args.min_severity == "low" and not args.signals):
            continue
        if args.category and args.category.lower() not in (a["rule_id"].lower(), a["category"].lower()):
            continue
        ids = ", ".join(t["id"] for t in a["mitre"]["attack"] + a["mitre"]["atlas"])
        sev = col(a["severity"], a["severity"].upper().ljust(9))
        print(f"{a['ts'][11:19]} {sev} [{a['rule_id']}] {a['title']}")
        print(f"          user={a['user']} host={a['host']} session={a['session_id']}  MITRE: {ids}")
        print(f"          evidence: {a['evidence']['snippet'][:150]}")
        print(f"          action:   {a['recommended_action'][:150]}")
        print(f"          response: {', '.join(r['action'] for r in a['response_actions']) or '-'}")
    print("\nEvaluation against labelled sample:")
    print("\n".join(evaluate(eng)))


if __name__ == "__main__":
    main()
