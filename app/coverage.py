"""Detection coverage view: which MITRE ATT&CK / ATLAS techniques the rules map to, and how much evidence backs each.

Computed from the rule catalog (app/catalog.py) and the technique table (app/mitre.py), so it cannot drift from the rules.
Read it honestly: this is coverage of the *coding-agent attack surface this monitor watches*, not of ATT&CK as a whole.
Tactics with no mapped technique are marked in or out of scope so a gap is a visible decision, not an accident."""
from __future__ import annotations

from .catalog import LOGIC, RULE_CATALOG
from .mitre import TECHNIQUES, technique

ATTACK_TACTICS = ["Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence", "Privilege Escalation",
                  "Stealth", "Defense Impairment", "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control",
                  "Exfiltration", "Impact"]
# Tactics this monitor does not try to cover, and who does. Stated so an empty column is read as a decision.
OUT_OF_SCOPE = {
    "Reconnaissance": "Outside the bank's telemetry (external). Threat-intel / attack-surface tooling.",
    "Resource Development": "Attacker-side activity. Only the part we can see (hallucinated or look-alike packages, D3) is mapped under Initial Access.",
    "Lateral Movement": "Network / endpoint detection in the main SIEM and EDR. This monitor sees the agent session, not the network.",
    "Discovery": "Only cloud discovery after a leaked key is seen (D10 alerts carry T1580; alert level, not counted here). Host and network discovery belong to EDR.",
}
# Tactics with no headline technique that are still partly seen at alert level. Shown as the note on the gap, so a gap
# is explained rather than looking like an accident, and so the view does not hide what individual alerts carry.
GAP_NOTES = {
    "Privilege Escalation": "No rule has a headline technique here. Alert level only: D4 tags sudo run by an agent and local privilege "
                            "persistence with T1548.003; not counted as coverage.",
    "Collection": "C3 detects collection followed by exfiltration but maps only the credential (T1552.001) and exfiltration techniques; "
                  "a Collection technique such as T1005 is not mapped yet.",
}
SPLIT = " / "


def build(validation: dict | None = None) -> dict:
    per_rule = (validation or {}).get("per_rule", {})
    by_tech: dict[str, dict] = {}
    for rid, r in RULE_CATALOG.items():
        for tid in LOGIC.get(rid, {}).get("techniques", []):
            if tid not in TECHNIQUES:
                continue
            name, tactic, fw = TECHNIQUES[tid]
            t = by_tech.setdefault(tid, {"id": tid, "url": technique(tid)["url"], "name": name, "tactics": [x.strip() for x in tactic.split(SPLIT)], "framework": fw, "rules": []})
            t["rules"].append(rid)
    for t in by_tech.values():
        t["rules"] = sorted(set(t["rules"]), key=lambda x: (x[0] != "D", int(x[1:])))
        t["attack_cases"] = sum(per_rule.get(r, {}).get("detected", 0) for r in t["rules"])
        t["validated"] = t["attack_cases"] > 0
    matrix = []
    for tac in ATTACK_TACTICS:
        techs = sorted((t for t in by_tech.values() if t["framework"] == "attack" and tac in t["tactics"]), key=lambda t: t["id"])
        matrix.append({"tactic": tac, "techniques": techs, "scope": "covered" if techs else ("out of scope" if tac in OUT_OF_SCOPE else "gap"),
                       "note": OUT_OF_SCOPE.get(tac) or ("" if techs else GAP_NOTES.get(tac, ""))})
    atlas: dict[str, list] = {}
    for t in sorted((t for t in by_tech.values() if t["framework"] == "atlas"), key=lambda t: t["id"]):
        for tac in t["tactics"]:
            atlas.setdefault(tac, []).append(t)
    rules = []
    for rid, r in RULE_CATALOG.items():
        rules.append({"id": rid, "name": r["name"], "techniques": LOGIC.get(rid, {}).get("techniques", []), "attack_cases": per_rule.get(rid, {}).get("detected", 0),
                      "benign_cases": per_rule.get(rid, {}).get("benign", 0)})
    n_attack = sum(t["framework"] == "attack" for t in by_tech.values())
    n_atlas = len(by_tech) - n_attack
    return {
        "matrix": matrix, "atlas": [{"tactic": k, "techniques": v} for k, v in sorted(atlas.items())], "rules": rules,
        "totals": {"attack_techniques": n_attack, "atlas_techniques": n_atlas, "rules": len(RULE_CATALOG),
                   "tactics_covered": sum(m["scope"] == "covered" for m in matrix), "tactics_out_of_scope": sum(m["scope"] == "out of scope" for m in matrix),
                   "tactics_gap": sum(m["scope"] == "gap" for m in matrix), "tactics_total": len(ATTACK_TACTICS)},
        "caveat": ("Coverage of the coding-agent attack surface this monitor watches, not of ATT&CK as a whole. The tick means the labelled corpus "
                   "contains attacks that the mapped rule catches. The evidence is per rule, not per technique (a rule that maps to three techniques shows the same count on each), "
                   "and the corpus is synthetic and written by the rule authors. Only each rule's headline techniques are counted; some alerts carry extra techniques that are not counted here. "
                   "ATT&CK IDs were checked against ATT&CK v20 (May 2026; v19 revoked the T1562 sub-techniques used earlier) and ATLAS IDs against dataset v5.6.0: re-verify at attack.mitre.org and atlas.mitre.org before external use."),
    }
