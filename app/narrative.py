"""Plain-English case summary for the analyst on shift.

A three-person SOC reads the first lines of a case and decides. So every case gets, deterministically:
  verdict       what this probably is, with a confidence and the reasons
  what_happened the story in order, one sentence per step (no rule jargon)
  why_it_matters the consequence if nobody acts
  do_now        the single next action and its deadline
  ask           the one question that settles it (usually put to the developer or the owner)
  not_sure      what this telemetry cannot tell us
No model writes this text: templates over structured evidence, so it cannot be steered by the content it summarises."""
from __future__ import annotations

SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
T = lambda a: a["ts"][11:16] + "Z"


def _sig(a, n=2):
    return "; ".join(a["evidence"].get("signals", [])[:n])


def step(a: dict) -> str:
    """One sentence for one alert, no rule IDs."""
    e, r, t = a["evidence"], a["rule_id"], T(a)
    if r == "D1":
        return f"{t} The agent read content from outside the bank that contains instructions aimed at an AI ({_sig(a)})."
    if r == "D2":
        if e.get("kinds"):
            return f"{t} {', '.join(e['kinds'])} appeared in {e.get('where', 'agent activity')}."
        return f"{t} The agent opened a credential file ({', '.join(e.get('paths', [])[:2])})."
    if r == "D3":
        pk = e.get("package", "a package")
        return f"{t} {a['title']}."
    if r == "D4":
        how = e.get("approval", "")
        ran = " It ran." if e.get("executed") else (" It did not complete." if e.get("executed") is False else "")
        who = {"auto-approved": "The agent ran it without asking the developer", "inside reverse shell": "A remote person typed it into the shell"}.get(how, "A command ran")
        return f"{t} {who}: {e.get('label', a['title'])} — {e.get('command', '')}.{ran}{' EDR confirms it.' if e.get('confirmed_by') else ''}"
    if r == "D5":
        return f"{t} {a['title']} ({_sig(a, 2)})."
    if r == "D6":
        return f"{t} {a['title']} ({_sig(a, 2)})."
    if r == "D7":
        return f"{t} {a['title']}."
    if r == "D8":
        return f"{t} {a['title']}."
    if r == "D9":
        return f"{t} {e.get('scm_label', 'A repository control')} on {e.get('repo_name') or 'a repository'} by {e.get('actor')} using {e.get('via') or 'the web UI'}."
    if r == "D10":
        return f"{t} {a['title']}."
    return f"{t} {a['title']}."


LEAD_ORDER = ["C1", "C2", "C3"]


def _lead(alerts):
    case_alerts = [a for a in alerts if a.get("tier") != "signal"] or alerts
    for rid in LEAD_ORDER:
        for a in case_alerts:
            if a["rule_id"] == rid:
                return a
    exposed = [a for a in case_alerts if a["rule_id"] == "D10"]
    if exposed:
        return max(exposed, key=lambda a: SEV_RANK[a["severity"]])
    return max(case_alerts, key=lambda a: (SEV_RANK[a["severity"]], -ord(a["rule_id"][-1])))


def _verdict(lead, alerts, why):
    r, sev, e = lead["rule_id"], lead["severity"], lead["evidence"]
    if r == "C1":
        return "Likely compromise: the agent acted on instructions hidden in outside content", "crit", "high"
    if r == "C2":
        conf = (why or {}).get("confidence", "medium")
        return "Likely compromise: the command came from untrusted content, not from the developer", "crit", conf
    if r == "C3":
        return "Likely data theft or a rogue agent: sensitive data was gathered, then sent out", "crit", "medium"
    if r == "D10":
        if "Containment failed" in lead["title"]:
            return "Containment failed: a token we thought was revoked is still being accepted", "crit", "high"
        if "Exposed access key" in lead["title"]:
            return "Credential theft in progress: a key the agent leaked is being used", "crit", "high"
        if "logging" in lead["title"].lower():
            return "Defence evasion in the cloud control plane", "crit", "high"
        return "Suspicious use of a developer credential", "high", "medium"
    if r == "D4":
        if sev == "critical":
            return "Likely malicious execution on a developer machine", "crit", "high"
        return "Risky command run by the agent — verify intent", "high" if sev == "high" else "med", "medium"
    if r == "D3":
        return ("Likely malicious package installed" if sev in ("critical", "high") else "Questionable dependency — verify"), "crit" if sev == "critical" else "high" if sev == "high" else "med", "medium" if sev != "critical" else "high"
    if r == "D2":
        return "Live credential exposed — policy breach that needs rotation", "high", "high"
    if r == "D5":
        return ("Data-protection event: customer data left the approved boundary" if e.get("pii_count") or "PII" in _sig(lead, 5) else "Policy breach: traffic to an unapproved destination"), "high", "high"
    if r == "D6":
        return "Persistence risk: agent instructions or tools were changed", "high" if sev == "high" else "med", "medium"
    if r == "D7":
        return "Risky source-control action — confirm with the developer", "high" if sev == "high" else "med", "medium"
    if r == "D8":
        if sev == "critical":
            return "Likely deliberate blinding: telemetry stopped after a log-evasion command", "crit", "high"
        return "Monitoring gap: treat as a platform fault first, but review the gap", "med", "medium"
    if r == "D9":
        return "A source-control safeguard was weakened — confirm with the actor", "high" if sev in ("high", "critical") else "med", "medium"
    return "Needs review", "med", "low"


WHY = {
    "C1": "The agent holds the developer's credentials. If it follows hidden instructions it can read secrets, run code and send data out without anyone noticing.",
    "C2": "Someone who controls a web page, issue or package decided what the agent ran on a bank machine.",
    "C3": "Credentials or customer data may already be with a third party; rotation and notification clocks start now.",
    "D10": "A working credential in the wrong hands means direct access to bank systems, not just a developer laptop.",
    "D4": "Code is running with the developer's privileges and may have opened a way back in.",
    "D3": "Install scripts run immediately with the developer's or CI's access; the package may already have harvested secrets.",
    "D2": "A pasted or generated credential is effectively public once it is in code, a prompt or a commit.",
    "D5": "Customer data in an unapproved model is a reportable data-protection event for a licensed bank.",
    "D6": "Poisoned rules and tool configs persist and spread to every developer who pulls the repository.",
    "D7": "Git is both the system of record and a way to copy code out; history rewrites are hard to undo.",
    "D8": "Attackers blind monitoring before acting; whatever happens next on this device is unobserved.",
    "D9": "Branch protection, secret scanning and repository visibility are the safeguards that stop bad code and leaks.",
}
ASK = {
    "C1": "Ask {user}: did you ask the agent to run this? (The expected answer is no.)",
    "C2": "Ask {user}: did you ask the agent to run this? (The expected answer is no.)",
    "C3": "Ask {user} why the data was needed and whether they sent it knowingly.",
    "D10": "Ask {user} whether they are using the credential from this address right now.",
    "D4": "Ask {user}: did you ask for this command, or approve it?",
    "D3": "Ask the owner of {repo}: was this package intended?",
    "D2": "Ask {user}: which system does this credential belong to, and is it live?",
    "D5": "Ask {user} why this data was in the prompt; ask the DPO to assess reporting.",
    "D6": "Ask the repo owner whether this change went through review.",
    "D7": "Ask {user} what they were trying to do with this branch or remote.",
    "D8": "Contact {user} or check whether the device is online before assuming tampering.",
    "D9": "Ask {actor} whether they made this change.",
}


def build(case: dict, alerts: list[dict], why: dict | None, decisions: list[dict], prio: dict) -> dict:
    alerts = sorted(alerts, key=lambda a: (a["ts"], a["alert_id"]))
    case_alerts = [a for a in alerts if a.get("tier") != "signal"] or alerts
    lead = _lead(alerts)
    label, tone, conf = _verdict(lead, alerts, why)
    corr = {"C1", "C2", "C3"}
    steps, merged = [], {}
    for a in case_alerts:
        if a["rule_id"] in corr:
            continue
        if a["rule_id"] == "D10" and a["title"].startswith("Exposed access key"):      # one line for a burst of calls with the same stolen key
            m = merged.get("key")
            if m:
                m["calls"].append(a["evidence"].get("api_event"))
                continue
            merged["key"] = m = {"calls": [a["evidence"].get("api_event")], "idx": len(steps)}
            steps.append(a)
            continue
        steps.append(step(a))
    if "key" in merged:
        a, m = steps[merged["key"]["idx"]], merged["key"]
        e = a["evidence"]
        steps[m["idx"]] = (f"{T(a)} The leaked key …{(e.get('access_key') or '')[-4:]} was used from {e.get('source_ip')} "
                           f"({len(m['calls'])} call{'s' if len(m['calls']) > 1 else ''}: {', '.join(dict.fromkeys(m['calls']))}).")
    if why and why.get("link"):
        steps.insert(0, f"{why['link']['ts'][11:16]}Z The agent ingested {why['link']['source']}: the command it later ran is written in that content.")
    pending = [d for d in decisions if d["status"] == "pending"]
    first = case_alerts[0]
    who = first.get("user") or "the developer"
    do_now = (f"{pending[0]['due']}: {pending[0]['action']}" if pending else "No decision is waiting — review the story and close the case, or add a note.")
    if prio["level"] == "P4" and not pending:
        do_now = "Low risk — review at the next opportunity and close as true or false positive."
    ask = ASK.get(lead["rule_id"], "Ask {user} what they were doing.").format(
        user=who, repo=first.get("repo") or "the repository", actor=lead["evidence"].get("actor") or who)
    srcs = sorted({a["evidence"].get("source") for a in case_alerts if a["evidence"].get("source")})
    not_sure = []
    if why:
        not_sure += why.get("blind_spots", [])[:1]
    if len(srcs) < 2:
        not_sure.append("Only one log source saw this; corroborate before closing.")
    return {
        "verdict": {"label": label, "tone": tone, "confidence": conf},
        "what_happened": steps[:6],
        "why_it_matters": WHY.get(lead["rule_id"], "Needs analyst review."),
        "do_now": do_now,
        "ask": ask,
        "not_sure": not_sure,
        "priority": prio,
    }
