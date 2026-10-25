"""Case analysis: *why* did the flagged action happen, and what is connected to it.

Everything here is deterministic and works only on structured evidence already collected (no model call).
  find_link   provenance link: does the flagged action's text (command, host, package ...) appear in untrusted
              content the agent ingested earlier in the same session?
  origin      hypothesis-driven triage: content-steered / poisoned config / compromised agent / human / mistake
  build_graph entity graph (user, host, agent, content, actions, files, destinations) plus IOC list
"""
from __future__ import annotations

import calendar
import hashlib
import re
import time

from . import config as C
from .detectors import host_in, is_agent_config, snip

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URLHOST = re.compile(r"https?://([A-Za-z0-9.-]+)")
ACTION_TYPES = {"shell_command", "package_install", "git_op", "api_call", "network_egress", "file_edit"}
REVERSE = re.compile(r"/dev/tcp/|bash\s+-i\s*>&|\bnc(?:at)?\b[^\n]*\s-[a-z]*e\b")
DESTRUCTIVE = re.compile(r"\brm\s+-(?:rf|fr)\b|\bdrop\s+(?:table|database)\b|\bmkfs\b", re.I)
PIPE_SHELL = re.compile(r"\b(?:curl|wget)\b[^|;\n]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b")


def _ts(s: str) -> float:
    try:
        return calendar.timegm(time.strptime(s, "%Y-%m-%dT%H:%M:%SZ"))
    except Exception:
        return 0.0


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s or "").strip().lower()


def action_text(etype: str, d: dict) -> str:
    return {"shell_command": d.get("command"), "network_egress": d.get("dest_host"), "package_install": d.get("package"),
            "git_op": d.get("remote_url"), "api_call": d.get("host"), "file_edit": d.get("diff_added")}.get(etype) or ""


def indicators(text: str) -> set[str]:
    found = set(IPV4.findall(text)) | set(URLHOST.findall(text))
    return {i for i in found if not host_in(i, C.ALLOWED_EGRESS_SUFFIXES)}


def _excerpt(content: str, needle: str) -> str:
    i = content.lower().find(needle.lower())
    if i < 0:
        return snip(content, 200)
    lo, hi = max(0, i - 70), min(len(content), i + len(needle) + 70)
    return ("…" if lo else "") + content[lo:hi].replace("\n", " ") + ("…" if hi < len(content) else "")


def find_link(etype: str, data: dict, ts: str, ctx: list[dict]) -> dict | None:
    """Strongest provenance link between an action and earlier untrusted content in the same session."""
    text = action_text(etype, data)
    if not text:
        return None
    n, inds, best = _norm(text), indicators(text), None
    for item in reversed(ctx):
        if item["ts"] > ts:
            continue
        c = _norm(item["text"])
        if len(n) >= 12 and n in c:
            return {"strength": "verbatim", "source": item["label"], "event_id": item["event_id"], "ts": item["ts"],
                    "excerpt": _excerpt(item["text"], text), "indicators": sorted(inds)}
        hit = sorted(i for i in inds if i.lower() in c)
        if hit and not best:
            best = {"strength": "indicator", "source": item["label"], "event_id": item["event_id"], "ts": item["ts"],
                    "excerpt": _excerpt(item["text"], hit[0]), "indicators": hit}
    return best


def _task_fit(prompt: str, etype: str, d: dict) -> tuple[bool | None, str]:
    p, cmd = (prompt or "").lower(), d.get("command", "") if etype == "shell_command" else ""
    if REVERSE.search(cmd):
        return False, "An interactive shell to an external host is not a step in any developer task."
    if DESTRUCTIVE.search(cmd):
        ok = any(k in p for k in ("delete", "remove", "clean", "reset", "wipe", "drop", "purge", "rm "))
        return ok, ("The prompt asks for removal." if ok else "The prompt did not ask for anything to be deleted.")
    if PIPE_SHELL.search(cmd):
        ok = any(k in p for k in ("install", "setup", "bootstrap")) and not indicators(cmd)
        return ok, ("Install-style task and an approved host." if ok else "Running a remote script from a non-approved host is not implied by the prompt.")
    return None, "The monitor cannot judge task relevance for this action type."


def origin(alerts: list[dict], raw: list[dict], ctx: list[dict]) -> dict | None:
    """Why did the first flagged action happen? Returns verdict, evidence and ranked hypotheses."""
    flagged = {e for a in alerts for e in a.get("evidence", {}).get("event_ids", [])}
    acts = [r for r in raw if r["event_id"] in flagged and r["type"] in ACTION_TYPES]
    if not acts:
        return None
    act = sorted(acts, key=lambda r: r["ts"])[0]
    d, etype = act["data"], act["type"]
    link = find_link(etype, d, act["ts"], ctx)
    prompts = [r for r in raw if r["type"] == "prompt" and r["ts"] <= act["ts"]]
    prompt = prompts[-1]["data"].get("text", "") if prompts else ""
    fit, fit_why = _task_fit(prompt, etype, d)
    said = [r for r in raw if r["type"] == "agent_message" and r["ts"] <= act["ts"] and _ts(act["ts"]) - _ts(r["ts"]) <= 300]
    agent_said = said[-1]["data"].get("text", "") if said else ""
    before = [c for c in ctx if c["ts"] <= act["ts"]]
    cfg = [a for a in alerts if a["rule_id"] == "D6"] or [
        r for r in raw if r["ts"] <= act["ts"] and r["type"] in ("file_edit", "file_read") and is_agent_config(r["data"].get("path", ""))]
    approved = d.get("approved_by")
    via_shell = "reverse shell" in (d.get("parent_process") or "")
    if via_shell:
        who = "a remote party typing into an existing reverse shell (parent process is the shell, not the agent)"
    elif approved == "auto":
        who = "the agent itself, auto-approved: no human saw the command before it ran"
    elif approved == "pipeline":
        who = "the CI pipeline"
    elif approved == "user":
        who = "the agent after the developer approved it"
    else:
        who = "the agent (approval state not recorded)"
    delta = int(_ts(act["ts"]) - _ts(link["ts"])) if link else None
    src = link["source"] if link else None

    h1 = {"id": "H1", "name": "Untrusted content steered the agent (indirect prompt injection)", "check": [
        "Open the source content and confirm who controls it", "Search other sessions and repos for the same text"]}
    if link and link["strength"] == "verbatim":
        h1.update(status="supported", **{"for": [f"The command text appears verbatim in content from {src} ingested {delta} s earlier."], "against": []})
    elif link:
        h1.update(status="supported", **{"for": [f"Indicator(s) {', '.join(link['indicators'])} appear in content from {src} ingested {delta} s earlier."], "against": []})
    elif before:
        h1.update(status="possible", **{"for": [f"Untrusted content was ingested before the action ({before[-1]['label']}), but no text links to it."], "against": []})
    else:
        h1.update(status="not_observed", **{"for": [], "against": ["No untrusted content was ingested in this session before the action."]})
        h1["check"] = ["Pull the full agent transcript: content ingested outside monitored channels (pasted text, a browser, local files) is invisible here"]
    h2 = {"id": "H2", "name": "Poisoned agent configuration, rules file or MCP server", "check": [
        "Diff rules / MCP / CI files against the last reviewed version", "Check which MCP servers the agent can reach"]}
    if cfg:
        h2.update(status="supported", **{"for": ["An agent configuration file or unapproved MCP server was involved in this session."], "against": []})
    else:
        h2.update(status="not_observed", **{"for": [], "against": ["No agent-config edit or unapproved MCP call seen in this session."]})
    unexplained = link is None and fit is False
    h3 = {"id": "H3", "name": "Compromised agent, extension or model channel (no instruction trail)", "check": [
        "List installed extensions and agent version with hashes", "Compare LLM gateway request and response logs for this session",
        "EDR: process ancestry of the command"]}
    if link:
        h3.update(status="unlikely", **{"for": [], "against": ["The action is explained by ingested content."]})
    elif unexplained:
        h3.update(status="open", **{"for": [fit_why, "No ingested content or approval explains the action."], "against": []})
    else:
        h3.update(status="possible", **{"for": [], "against": []})
    h4 = {"id": "H4", "name": "Developer ran or approved it deliberately", "check": [
        "Ask the developer", "Check terminal history for the typed command"]}
    if approved in ("auto", "none") or via_shell:
        h4.update(status="unlikely", **{"for": [], "against": ["Nobody approved it: " + who + "."]})
    else:
        h4.update(status="possible", **{"for": [f"Approval recorded: {approved}."], "against": []})
    h5 = {"id": "H5", "name": "Benign agent mistake", "check": ["Compare with the developer's stated task"]}
    if fit is True:
        h5.update(status="possible", **{"for": [fit_why], "against": []})
    else:
        h5.update(status="unlikely", **{"for": [], "against": [fit_why]})

    later = [r for r in raw if r["ts"] > act["ts"] and "reverse shell" in (r["data"].get("parent_process") or "") and r["event_id"] in flagged]
    findings = []
    if prompt:
        findings.append(f"The developer asked: “{snip(prompt, 140)}”. {fit_why}")
    findings.append(f"Executed by {who}.")
    if agent_said:
        findings.append(f"The agent itself said: “{snip(agent_said, 200)}”. Its stated reason is a claim, not proof: compare it with the developer's task.")
    if link:
        findings.append(f"Provenance: “{snip(link['excerpt'], 170)}” (from {src}, {delta} s before the action).")
    elif before:
        findings.append(f"{len(before)} untrusted content item(s) were read earlier, none contains the action text.")
    else:
        findings.append("No untrusted content was read in this session before the action.")
    if later:
        findings.append(f"{len(later)} later flagged command(s) ran inside the reverse shell. They were typed by the remote party, not the agent: this is hands-on-keyboard activity.")

    if link:
        conf = "high" if link["strength"] == "verbatim" else "medium"
        verdict = (f"Most likely content-steered, not a rogue agent: {'the exact command' if link['strength'] == 'verbatim' else 'an indicator in the command'} "
                   f"was supplied by untrusted content ({src}) {delta} s before it ran, and it was run by {who}.")
    elif cfg:
        conf, verdict = "medium", "Most likely steered by a poisoned agent configuration or MCP server involved in this session."
    elif unexplained:
        conf = "low"
        verdict = ("No observed content, prompt or approval explains this action. Treat the agent, its extensions or the model channel as potentially "
                   "compromised until the transcript and extension inventory are checked.")
    else:
        conf, verdict = "low", "The telemetry does not establish a cause. Review the transcript."
    return {"action": {"event_id": act["event_id"], "ts": act["ts"], "type": etype, "text": snip(action_text(etype, d), 160)},
            "verdict": verdict, "confidence": conf, "link": link, "initiator": who, "prompt": prompt, "task_fit": {"fit": fit, "why": fit_why},
            "findings": findings, "hypotheses": [h1, h2, h3, h4, h5],
            "agent_said": agent_said or None,
            "blind_spots": ([] if agent_said else ["The model's reasoning and full transcript are not in this telemetry; LLM-gateway request/response logging is needed to confirm intent."]) + [
                "Only the agent's visible messages are logged, not its hidden reasoning." if agent_said else "No agent message was logged before this action.",
                            "Content the agent saw outside monitored channels (pasted text, local files not read through the IDE) is invisible."]}


# ----------------------------------------------------------------------------- entity graph + IOCs
def build_graph(case: dict, alerts: list[dict], raw: list[dict], link: dict | None) -> dict:
    flagged = {e for a in alerts for e in a.get("evidence", {}).get("event_ids", [])}
    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    iocs: dict[str, dict] = {}

    def node(kind, key, label, sub="", ioc=False, flag=False, ts=None):
        nid = f"{kind}:{key}"
        if nid not in nodes and len(nodes) < 18:
            nodes[nid] = {"id": nid, "kind": kind, "label": snip(label, 34), "sub": snip(sub, 60), "ioc": ioc, "flagged": flag, "ts": ts}
        return nid if nid in nodes else None

    def edge(a, b, label, kind="flow", ts=None):
        if a and b:
            edges.append({"from": a, "to": b, "label": label, "kind": kind, "ts": ts})

    def ioc(typ, value, role, ts, eid):
        k = f"{typ}:{value}"
        if k not in iocs:
            iocs[k] = {"type": typ, "value": value, "role": role, "first_seen": ts, "event_ids": []}
        iocs[k]["event_ids"].append(eid)

    first = alerts[0]
    u = node("user", first["user"], first["user"], "developer / identity")
    h = node("host", first["host"], first["host"], "endpoint")
    ag = node("agent", case["session_id"], first.get("agent") or "agent", f"session {case['session_id']}")
    rp = node("repo", first.get("repo") or "-", first.get("repo") or "–", "repository") if first.get("repo") else None
    edge(u, ag, "uses"); edge(ag, h, "runs on"); edge(ag, rp, "works in")
    cmd_nodes: dict[str, str] = {}
    for r in raw:
        d, t, eid, ts = r["data"], r["type"], r["event_id"], r["ts"]
        fl = eid in flagged
        if t == "tool_result" and d.get("origin_trust") == "untrusted":
            carried = bool(link and link["event_id"] == eid)
            n = node("content", eid, d.get("tool", "content"), "untrusted content" + (" · carried the command" if carried else ""), ioc=carried or fl, flag=fl, ts=ts)
            edge(n, ag, f"ingested {ts[11:19]}", ts=ts)
            if carried:
                ioc("content", d.get("tool", "content"), "Untrusted content source that carried the command", ts, eid)
        elif t == "shell_command" and fl:
            cmd = d.get("command", "")
            n = node("command", eid, cmd, "executed " + ts[11:19] + (" · inside reverse shell" if d.get("parent_process") else ""), flag=True, ts=ts)
            cmd_nodes[eid] = n
            if d.get("parent_process"):
                prev = [v for k, v in cmd_nodes.items() if k != eid]
                edge(prev[-1] if prev else ag, n, "typed by remote party", kind="attacker", ts=ts)
            else:
                edge(ag, n, f"executed ({d.get('approved_by', '?')})", ts=ts)
            ioc("command", "sha256:" + hashlib.sha256(cmd.encode()).hexdigest()[:16], "Flagged command (hash of the full text)", ts, eid)
            for i in sorted(indicators(cmd)):
                role = "Reverse-shell C2 endpoint" if REVERSE.search(cmd) else "Payload / staging host"
                dn = node("dest", i, i, role, ioc=True, ts=ts)
                edge(n, dn, "connects to", kind="ioc", ts=ts)
                ioc("ip" if IPV4.fullmatch(i) else "domain", i, role, ts, eid)
        elif t == "network_egress" and not host_in(d.get("dest_host"), C.ALLOWED_EGRESS_SUFFIXES):
            host = d.get("dest_host", "")
            dn = node("dest", host, host, f"{d.get('bytes_out', 0):,} B out · {d.get('proc', '')}", ioc=True, flag=fl, ts=ts)
            edge(ag, dn, f"egress {ts[11:19]}", kind="ioc", ts=ts)
            ioc("ip" if IPV4.fullmatch(host) else "domain", host, "External egress destination", ts, eid)
        elif t == "file_read" and fl:
            fn = node("file", d.get("path"), d.get("path", "file"), "sensitive file read", flag=True, ts=ts)
            edge(ag, fn, f"read {ts[11:19]}", ts=ts)
            ioc("file", d.get("path", ""), "Sensitive file exposed to the agent", ts, eid)
        elif t == "file_edit" and fl:
            fn = node("file", d.get("path"), d.get("path", "file"), "edited by agent", flag=True, ts=ts)
            edge(ag, fn, f"edited {ts[11:19]}", ts=ts)
            ioc("file", d.get("path", ""), "File with flagged content", ts, eid)
        elif t == "package_install" and fl:
            pn = node("package", d.get("package"), f"{d.get('package')}@{d.get('version')}", f"{d.get('registry')} registry", ioc=True, flag=True, ts=ts)
            edge(ag, pn, f"installed {ts[11:19]}", kind="ioc", ts=ts)
            ioc("package", f"{d.get('package')}@{d.get('version')}", "Suspect package", ts, eid)
        elif t == "api_call" and fl:
            host = d.get("host", "")
            dn = node("dest", host, host, f"LLM endpoint · {d.get('bytes_out', 0):,} B", ioc=not host_in(host, C.APPROVED_LLM_HOSTS), flag=True, ts=ts)
            edge(ag, dn, f"sent context {ts[11:19]}", kind="ioc", ts=ts)
            for f in d.get("context_files", [])[:2]:
                edge(node("file", f, f, "in context", flag=True), dn, "included in request", ts=ts)
            if not host_in(host, C.APPROVED_LLM_HOSTS):
                ioc("domain", host, "Unapproved LLM endpoint", ts, eid)
        elif t == "git_op" and fl and d.get("remote_url"):
            rn = node("dest", d["remote_url"], d["remote_url"], "git remote", ioc=True, flag=True, ts=ts)
            edge(ag, rn, f"push {ts[11:19]}", kind="ioc", ts=ts)
            ioc("url", d["remote_url"], "Foreign git remote", ts, eid)
    if link:
        cn = f"content:{link['event_id']}"
        first_cmd = next(iter(cmd_nodes.values()), None)
        if cn in nodes and first_cmd:
            edge(cn, first_cmd, "command text found in content", kind="link")
    if not [n for n in nodes.values() if n["kind"] not in ("user", "host", "agent", "repo")]:
        first_text = first.get("evidence", {}).get("snippet", "")
        if first_text:
            edge(h, node("command", "host-event", first_text, "host-level event", flag=True), "observed", ts=first["ts"])
    return {"nodes": list(nodes.values()), "edges": edges, "iocs": list(iocs.values())}
