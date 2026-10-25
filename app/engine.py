"""Streaming detection engine.

Pipeline per event:  parse/validate -> normalise -> detect (detectors.py) -> correlate (C1, D8) -> alert -> case -> respond.
Stateful logic that needs history lives here:
  D8  telemetry silence / log tampering (event-time clock, plus wall-clock tick in live mode)
  C1  kill-chain correlation (injection -> privileged action / egress inside one session)
  Cases: alerts are grouped per session into a case with a workflow (status, owner, notes, history).
"""
from __future__ import annotations

import json
import re
import time
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

from . import audit as A
from . import config as C
from . import narrative
from .analysis import action_text, build_graph, find_link, origin as analyse_origin
from .catalog import (ACTION_LABEL, CAPABILITIES, DECISION_DEFS, DECISION_DUE, ENGINE_TYPES, FEED_INFO, LOGIC, RULE_CATALOG,
                      RULE_DECISIONS, RULE_OWNERSHIP, SLA_TARGETS, STAGE)
from .detectors import DETECTORS, host_in, make_alert, snip
from .mitre import RULES
from .response import Responder

_AGENTS = (r"(?:log-?shipper|auditd|auditbeat|filebeat|fluent\w*|vector(?![\w-])|td-agent|telegraf|nxlog|rsyslog(?:d)?|syslog-ng|osquery\w*|"
           r"falcon-?sensor|cbagent\w*|sentinel\w*|wazuh\w*|splunk\w*|sysmon\w*|edr\w*)")
TAMPER_CMD = re.compile(
    r"(?i)(?:\b(?:systemctl|service|initctl|launchctl)\b[^\n;|&]*\b(?:stop|disable|mask|kill|unload|bootout)\b[^\n;|&]*" + _AGENTS + r"|"
    r"\b(?:systemctl|service)\s+" + _AGENTS + r"\s+(?:stop|disable|kill)\b|"                                       # `service auditd stop`
    r"\b(?:pkill|killall|kill)\b[^\n;|&]*" + _AGENTS + r"|"
    r"\bchmod\s+(?:-\w+\s+)?(?:-x|000|a-x)\s+\S*" + _AGENTS + r"|"                                               # make the sensor unrunnable
    r"\b(?:mv|rm|unlink)\s+(?:-\w+\s+)*\S*(?:/" + _AGENTS + r"|/var/log/audit|shipper)|"
    r"\bauditctl\s+(?:-e\s*0|-D)\b|"                                                                          # turn Linux auditing off / delete rules
    r"(?:^|[;&|]\s*|\s)(?:>|:\s*>|truncate\s+-s\s*0)\s*/var/log/\S+|\bshred\s+\S*/var/log/|\bjournalctl\s+--vacuum|"   # wipe logs
    r"\bunset\s+https?_proxy|export\s+no_proxy=\*|iptables\s+[^\n]*-j\s+DROP[^\n]*(?:514|5044|9200|443)|"
    r"\b(?:Stop-Service|Set-Service)\b[^\n]*" + _AGENTS + r"|\bsc(?:\.exe)?\s+(?:stop|config)\s+\S*" + _AGENTS + r"|"   # Windows
    r"\bwevtutil\s+cl\b|\bClear-EventLog\b|\bSet-MpPreference\b[^\n]*Disable(?:RealtimeMonitoring|IntrusionPreventionSystem))")
SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
PRIORITY_SEV = {"P1": "critical", "P2": "high", "P3": "medium", "P4": "low"}     # SLA wording is shared between severity and priority
LANES = {"prompt": "Prompt", "agent_message": "Agent", "tool_result": "Content in", "mcp_tool_call": "Content in", "shell_command": "Shell", "process_start": "Shell",
         "file_read": "Files · git · packages", "file_edit": "Files · git · packages", "git_op": "Files · git · packages", "package_install": "Files · git · packages",
         "api_call": "Network · LLM", "network_egress": "Network · LLM", "dns_query": "Network · LLM",
         "audit_event": "Identity · cloud · SCM", "cloud_api": "Identity · cloud · SCM", "auth_event": "Identity · cloud · SCM"}
KNOWN_TYPES = {"prompt", "file_read", "file_edit", "shell_command", "git_op", "api_call", "network_egress",
               "mcp_tool_call", "tool_result", "package_install", "heartbeat", "agent_message", "process_start", "dns_query",
               "audit_event", "cloud_api", "auth_event"}
# Control-plane logs carry no agent session id. They are joined to the developer's agent session by user (identity plane) or by
# host (endpoint plane) when that session was active in the last LINK_WINDOW seconds: this is how a cloud call becomes part of the story.
IDENTITY_SOURCES = {"github_audit", "cloud_audit", "idp_auth"}
HOST_SOURCES = {"edr", "dns"}
LINK_WINDOW = 900
STATUSES = ["new", "triaged", "investigating", "contained", "closed_tp", "closed_fp"]
CLOSED = {"closed_tp", "closed_fp"}
MAX_TEXT = 20_000        # per string field: bounds regex cost (ReDoS / memory) on hostile input
MAX_SESSIONS = 5_000     # bounded state
SESSION_EVENTS = 300


def parse_ts(s: str) -> float:
    return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def summarize(ev: dict) -> str:
    t, d = ev["event_type"], ev.get("data", {})
    s = {
        "prompt": lambda: d.get("text", ""),
        "file_read": lambda: d.get("path", ""),
        "file_edit": lambda: f"{d.get('path', '')}  +{d.get('diff_added', '')[:120]}",
        "shell_command": lambda: d.get("command", ""),
        "git_op": lambda: f"git {d.get('op')} {d.get('branch', '')}{' --force' if d.get('force') else ''} → {d.get('remote_url') or d.get('remote', '')}",
        "api_call": lambda: f"{d.get('host')} · {d.get('model', '')} · {d.get('bytes_out', 0):,} B",
        "network_egress": lambda: f"{d.get('dest_host')}:{d.get('dest_port')} · {d.get('bytes_out', 0):,} B · {d.get('proc', '')}",
        "package_install": lambda: f"{d.get('manager')} {d.get('package')}@{d.get('version')} ({d.get('registry')} registry)",
        "mcp_tool_call": lambda: f"{d.get('server')}.{d.get('tool')} (approved={d.get('server_approved')})",
        "tool_result": lambda: d.get("content", ""),
        "agent_message": lambda: d.get("text", ""),
        "process_start": lambda: f"{d.get('image', '')} {d.get('cmdline', '')}  ← {d.get('parent_image', '')}",
        "dns_query": lambda: f"{d.get('qtype', 'A')} {d.get('query', '')}",
        "audit_event": lambda: f"{d.get('action')} · {d.get('repo') or d.get('org', '')} · by {d.get('actor')} via {d.get('programmatic_access_type', 'web')}",
        "cloud_api": lambda: f"{d.get('eventName')} · {(d.get('userIdentity') or {}).get('userName', '?')} · from {d.get('sourceIPAddress')}" + (f" · {d['errorCode']}" if d.get("errorCode") else ""),
        "auth_event": lambda: f"{d.get('outcome')} · {d.get('app')} · {d.get('token_type')} · from {d.get('src_ip')}",
    }.get(t, lambda: "")
    return snip(str(s()), 170)


class Engine:
    def __init__(self, out_dir: Path | str | None = None):
        self.responder = Responder(out_dir)
        self.reset()

    # ------------------------------------------------------------------------------ state
    enricher = None                        # optional hook set by main.py: intel-list context for a case (enrichment only, never read by a rule)
    audit_enabled = True                   # the web sandbox and tests switch this off so they never write to the real audit log

    def reset(self) -> None:
        self.alerts: list[dict] = []
        self.sessions: dict[str, dict] = {}
        self.hosts: dict[str, dict] = {}
        self.cases: dict[str, dict] = {}
        self.ai_reviews: dict[str, list] = {}                        # advisory only: no code path in the engine reads these to decide anything
        self.case_seq = 0
        self.feeds: dict[str, dict] = {}
        self.user_bytes: dict[str, deque] = defaultdict(lambda: deque(maxlen=500))
        self.exposed_keys: dict[str, dict] = {}                      # hashed cloud key IDs that a session leaked (D2) -> where; D10 watches for their use
        self.dns_hist: dict[tuple, deque] = defaultdict(lambda: deque(maxlen=200))
        self.secret_reads: dict[str, deque] = defaultdict(lambda: deque(maxlen=50))
        self.frozen_users: dict[str, dict] = {}                      # user -> when their agent tokens were revoked (containment verification)
        self.recent_user: dict[str, dict] = {}
        self.recent_host: dict[str, dict] = {}
        self.seen: set[str] = set()
        self.counter = 0
        self.events_processed = 0
        self.clock = 0.0
        self.live = False
        self.metrics = {"lines_received": 0, "accepted": 0, "rejected": Counter(), "by_type": Counter(),
                        "by_source": Counter(), "unclassified": 0, "truncated": 0, "errors": 0}
        self.responder.reset()

    def _session(self, sid: str) -> dict:
        if sid not in self.sessions and len(self.sessions) >= MAX_SESSIONS:
            for k, v in self.sessions.items():          # evict the oldest session that never alerted
                if not v["alert_ids"]:
                    del self.sessions[k]
                    break
        return self.sessions.setdefault(sid, {"frozen": False, "injection_ts": None, "chain_fired": False,
                                              "alert_ids": [], "signal_ids": [], "collected": [], "c3": False, "user": None, "host": None, "prov": False,
                                              "events": deque(maxlen=SESSION_EVENTS), "raw": deque(maxlen=30), "ctx": deque(maxlen=20), "prompts": deque(maxlen=10)})

    # ------------------------------------------------------------------------------ ingest
    def ingest_lines(self, lines) -> dict:
        ok = bad = 0
        events = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            self.metrics["lines_received"] += 1
            try:
                ev = json.loads(line)
            except Exception:
                self.metrics["rejected"]["invalid JSON"] += 1
                bad += 1
                continue
            if not isinstance(ev, dict) or not all(ev.get(k) for k in ("ts", "event_type")) or not (
                    ev.get("session_id") or ev.get("source") in IDENTITY_SOURCES | HOST_SOURCES):
                self.metrics["rejected"]["missing required field (ts / event_type / session_id)"] += 1
                bad += 1
                continue
            try:
                parse_ts(ev["ts"])
            except Exception:
                self.metrics["rejected"]["bad timestamp"] += 1
                bad += 1
                continue
            if not isinstance(ev.get("data", {}), dict):
                self.metrics["rejected"]["data is not an object"] += 1
                bad += 1
                continue
            events.append(ev)
        events.sort(key=lambda e: e["ts"])
        for ev in events:
            self.safe_process(ev)
            ok += 1
        return {"ingested": ok, "rejected": bad}

    def safe_process(self, ev: dict) -> list[dict]:
        """A detector bug or malformed event must never stop the pipeline: count it, keep going."""
        try:
            return self.process(ev)
        except Exception:
            self.metrics["errors"] += 1
            return []

    def _normalise(self, ev: dict) -> None:
        ev.setdefault("data", {})
        ev.setdefault("host", "unknown")
        ev.setdefault("user", "unknown")
        ev.setdefault("source", "unknown")
        ev.setdefault("event_id", f"x{self.events_processed + 1:06d}")
        ev.setdefault("session_id", f"{ev['source']}:{ev['host'] if ev['source'] in HOST_SOURCES else ev['user']}")
        for k, v in list(ev["data"].items()):
            if isinstance(v, str) and len(v) > MAX_TEXT:
                ev["data"][k] = v[:MAX_TEXT]
                self.metrics["truncated"] += 1

    def process(self, ev: dict) -> list[dict]:
        self._normalise(ev)
        ts = parse_ts(ev["ts"])
        self.clock = max(self.clock, ts)
        self.events_processed += 1
        self.metrics["accepted"] += 1
        self.metrics["by_type"][ev["event_type"]] += 1
        self.metrics["by_source"][ev["source"]] += 1
        feed = self.feeds.setdefault(ev["source"], {"events": 0, "first": ts, "last": ts})
        feed["events"] += 1
        feed["last"] = max(feed["last"], ts)
        emitted: list[dict] = []
        self._link(ev, ts)

        for a in self._silence_check(self.clock):       # gaps are evaluated *before* this event refreshes its host
            emitted.append(a)
        if not (ev["source"] in IDENTITY_SOURCES and ev["host"] == "unknown"):
            self._track_host(ev, ts, emitted)

        if ev["event_type"] == "heartbeat":
            return emitted
        if ev["event_type"] not in KNOWN_TYPES:
            self.metrics["unclassified"] += 1

        sess = self._session(ev["session_id"])
        sess["user"], sess["host"] = ev["user"], ev["host"]
        entry = {"ts": ev["ts"], "event_id": ev["event_id"], "type": ev["event_type"], "source": ev["source"],
                 "summary": summarize(ev)}
        sess["events"].append(entry)
        if ev["host"] in self.hosts:
            self.hosts[ev["host"]]["recent"].append(entry)
        if ev["source"] not in IDENTITY_SOURCES | HOST_SOURCES and ev["event_type"] != "heartbeat":
            r = {"sid": ev["session_id"], "ts": ts, "host": ev["host"], "repo": ev.get("repo"), "agent": ev.get("agent")}
            self.recent_user[ev["user"]] = r
            self.recent_host[ev["host"]] = r
        d = ev["data"] if isinstance(ev.get("data"), dict) else {}
        sess["raw"].append({"event_id": ev["event_id"], "ts": ev["ts"], "type": ev["event_type"], "source": ev["source"],
                            "data": {k: (v[:800] if isinstance(v, str) else v[:10] if isinstance(v, list) else v) for k, v in d.items()}})
        if ev["event_type"] == "prompt":
            sess["prompts"].append(re.sub(r"\s+", " ", str(d.get("text", ""))).strip().lower())
        if ev["event_type"] == "tool_result" and d.get("origin_trust") == "untrusted":
            sess["ctx"].append({"event_id": ev["event_id"], "ts": ev["ts"], "label": d.get("tool") or "content", "text": str(d.get("content", ""))[:4000]})
        elif ev["event_type"] == "file_read" and d.get("trust") == "external":
            sess["ctx"].append({"event_id": ev["event_id"], "ts": ev["ts"], "label": d.get("path") or "file", "text": str(d.get("content_snippet", ""))[:4000]})

        new = []
        for det in DETECTORS:
            new += det(ev, self)
        fired = [x for x in (self._emit(a, sess) for a in new) if x]
        emitted += fired
        for a in fired:
            if a["rule_id"] == "D1" and a["severity"] != "low" and "AML.T0051.001" in [t["id"] for t in a["mitre"]["atlas"]]:
                sess["injection_ts"] = ts
        if ev["event_type"] == "process_start":
            self._confirm_exec(ev, sess)
        c1 = self._chain(ev, ts, sess, fired)
        if c1:
            emitted.append(c1)
        elif (c2 := self._provenance(ev, ts, sess, fired)):
            emitted.append(c2)
        elif (c3 := self._collect_exfil(ev, ts, sess, fired)):
            emitted.append(c3)
        return emitted

    # ------------------------------------------------------------------------------ linking, confirmation
    def _link(self, ev: dict, ts: float) -> None:
        """Join a control-plane event (cloud/SCM/identity by user, EDR/DNS by host) to the agent session that was active just before it."""
        src = ev["source"]
        if src in IDENTITY_SOURCES:
            r = self.recent_user.get(ev["user"])
        elif src in HOST_SOURCES:
            r = self.recent_host.get(ev["host"])
        else:
            return
        if r and 0 <= ts - r["ts"] <= LINK_WINDOW:
            ev["session_id"], ev["_linked"] = r["sid"], True
            self.metrics["joined"] = self.metrics.get("joined", 0) + 1
            if ev["host"] == "unknown":
                ev["host"] = r["host"]
            ev["repo"] = ev.get("repo") or r["repo"]
            ev["agent"] = ev.get("agent") or r["agent"]

    def _confirm_exec(self, ev: dict, sess: dict) -> None:
        """EDR saw the process start: upgrade 'the command was typed' to 'the command ran' on the alert that flagged it."""
        norm = lambda x: re.sub(r"\s+", " ", x or "").strip().lower()
        line = norm(ev["data"].get("cmdline"))
        for aid in sess["alert_ids"]:
            a = self.by_id(aid)
            cmd = norm((a or {}).get("evidence", {}).get("command", "")).rstrip("…")
            if a and a["rule_id"] == "D4" and cmd and (cmd[:60] in line or line[:60] in cmd) and not a["evidence"].get("confirmed_by"):
                a["evidence"].update(executed=True, confirmed_by="edr")
                a["evidence"]["signals"].append(f"execution confirmed by EDR (pid {ev['data'].get('pid', '?')})")
                a["evidence"]["event_ids"].append(ev["event_id"])

    # ------------------------------------------------------------------------------ C3
    def _collect_exfil(self, ev, ts, sess, fired) -> dict | None:
        """C3: something sensitive was gathered earlier in the session, then a channel out appeared. No injection needed: this is the
        pattern of a rogue agent, a compromised extension or a careless developer."""
        if sess["c3"] or sess["chain_fired"] or sess["prov"] or not sess["collected"]:
            return None
        earlier = [c for c in sess["collected"] if 0 <= ts - parse_ts(c["ts"]) <= C.CHAIN_WINDOW and c["alert_id"] not in {a["alert_id"] for a in fired}]
        if not earlier:
            return None
        exfil = None
        for a in fired:
            e = a["evidence"]
            if a["rule_id"] == "D5" and (e.get("event_type") in ("network_egress", "dns_query") or (e.get("event_type") == "api_call" and e.get("approved_endpoint") is False)):
                exfil = (a, e.get("dest") or e.get("host") or "an unapproved destination")
            elif a["rule_id"] == "D7" and e.get("remote") and "push" in a["title"].lower():
                exfil = (a, e["remote"])
        egress_only = (ev["event_type"] == "network_egress" and not host_in(ev["data"].get("dest_host"), C.ALLOWED_EGRESS_SUFFIXES))
        if not exfil and not egress_only:
            return None
        sess["c3"] = True
        what = sorted({c["what"] for c in earlier})
        dest = exfil[1] if exfil else ev["data"].get("dest_host")
        sev = "medium"
        if exfil:
            sev = "critical" if ({"credential file", "sensitive data"} & set(what)) else "high"
        stages = [a for a in (self.by_id(i) for i in sess["alert_ids"]) if a]
        stage_txt = " → ".join(f"[{a['rule_id']}] {a['title'][:70]}" for a in stages)
        al = make_alert(
            "C3", ev, sev, f"Collection then exfiltration: {', '.join(what)} gathered, then sent to {dest}",
            stage_txt + f" → OUT to {dest}",
            "Treat the data as disclosed: suspend the session, find what was gathered (see stages), rotate credentials, and check the destination "
            "against threat intel. Ask the developer whether they knowingly sent it.",
            ["T1552.001", "T1567", "AML.T0086"], key="c3",
            signals=[f"{', '.join(what)} collected {int(ts - parse_ts(earlier[0]['ts']))} s earlier", "outbound channel to a destination outside policy"],
            stages=[a["alert_id"] for a in stages], dest=dest)
        return self._emit(al, sess)

    # ------------------------------------------------------------------------------ C2
    def _provenance(self, ev, ts, sess, fired) -> dict | None:
        """C2: a privileged action whose text was supplied by untrusted content the agent ingested earlier."""
        if sess["chain_fired"] or sess["prov"] or not sess["ctx"]:
            return None
        if not [a for a in fired if a["rule_id"] in ("D2", "D4", "D5", "D7") and SEV_RANK[a["severity"]] >= 3]:
            return None
        link = find_link(ev["event_type"], ev["data"], ev["ts"], list(sess["ctx"]))
        if not link:
            return None
        said = re.sub(r"\s+", " ", action_text(ev["event_type"], ev["data"])).strip().lower()
        if len(said) >= 12 and any(said in p for p in sess["prompts"]):
            return None      # the developer asked for exactly this in their own prompt: not steered by the content
        sess["prov"] = True
        delta = int(ts - parse_ts(link["ts"]))
        verb = link["strength"] == "verbatim"
        stages = [a for a in (self.by_id(i) for i in sess["alert_ids"]) if a]
        al = make_alert(
            "C2", ev, "critical" if verb else "high",
            ("Provenance: the command was supplied by untrusted content" if verb else "Provenance: action matches indicators from untrusted content") + f" ({link['source']})",
            f"Content from {link['source']} at {link['ts'][11:19]}Z: “{link['excerpt']}”  →  executed {delta} s later: {action_text(ev['event_type'], ev['data'])[:120]}",
            "Treat the session as steered by untrusted content: declare an incident if the action executed, isolate the host and revoke credentials the "
            "session could reach, block the content source and hunt for it elsewhere.",
            ["AML.T0051.001", "AML.T0053", "T1059"], key="prov",
            signals=[f"{link['strength']} link to {link['source']}", f"{delta} s after the content was ingested"],
            link={k: link[k] for k in ("strength", "source", "event_id", "ts")}, stages=[a["alert_id"] for a in stages])
        al["evidence"]["event_ids"].append(link["event_id"])
        return self._emit(al, sess)

    # ------------------------------------------------------------------------------ alerts & cases
    def _emit(self, a: dict, sess: dict) -> dict | None:
        key = a.pop("_key")
        if key in self.seen:
            return None
        self.seen.add(key)
        self.counter += 1
        a["alert_id"] = f"A-{self.counter:04d}"
        ev_ = a["evidence"]
        a["tier"] = "signal" if a["severity"] == "low" else "case"
        if ev_.get("collected"):
            sess["collected"].append({"what": ev_["collected"], "ts": a["ts"], "alert_id": a["alert_id"]})
        if a["tier"] == "signal":
            # A signal is stored and searchable but never pages anyone and never opens a case. It joins a case if one exists or opens later.
            a["response_actions"], a["status"], a["case_id"] = [], "signal", None
            sess["signal_ids"].append(a["alert_id"])
            self.alerts.append(a)
            case = self.cases.get(a["session_id"])
            if case:
                case["alert_ids"].append(a["alert_id"])
                a["case_id"], a["status"] = case["case_id"], case["status"]
            self.responder.write_alert(a)
            return a
        a["response_actions"] = self.responder.apply(a, sess)
        if self.audit_enabled and A.AUDIT.enabled:
            for r in a["response_actions"]:
                A.AUDIT.log("system", "response_action", a["alert_id"], {"action": r.get("action"), "status": r.get("status"), "rule": a["rule_id"], "user": a.get("user")})
        if sess["frozen"] and a.get("user") and a["user"] not in self.frozen_users:
            self.frozen_users[a["user"]] = {"iso": a["ts"], "session": a["session_id"]}
        sess["alert_ids"].append(a["alert_id"])
        self.alerts.append(a)
        case = self._case_for(a)
        a["case_id"], a["status"] = case["case_id"], case["status"]
        self.responder.write_alert(a)
        return a

    def _case_for(self, a: dict) -> dict:
        sid = a["session_id"]
        case = self.cases.get(sid)
        if not case:
            self.case_seq += 1
            case = {"case_id": f"C-{self.case_seq:03d}", "session_id": sid, "status": "new", "owner": None,
                    "notes": [], "decisions": {}, "alert_ids": [], "severity": a["severity"], "user": a["user"], "host": a["host"],
                    "repo": a["repo"], "agent": a["agent"], "opened": a["ts"], "updated": a["ts"], "title": a["title"],
                    "history": [{"ts": iso(time.time()), "who": "system", "event": f"Case opened by {a['rule_id']}: {a['title']}"}]}
            self.cases[sid] = case
            if self.audit_enabled and A.AUDIT.enabled:
                A.AUDIT.log("system", "case_opened", case["case_id"], {"rule": a["rule_id"], "severity": a["severity"], "user": a.get("user"), "host": a.get("host")})
            for sig in (self.sessions.get(sid) or {}).get("signal_ids", []):     # weak signals seen earlier become context for the case
                al = self.by_id(sig)
                if al and sig not in case["alert_ids"]:
                    case["alert_ids"].append(sig)
                    al["case_id"], al["status"] = case["case_id"], case["status"]
        case["alert_ids"].append(a["alert_id"])
        case["updated"] = a["ts"]
        best = max((self.by_id(i) for i in case["alert_ids"] if self.by_id(i)),
                   key=lambda x: (SEV_RANK[x["severity"]], x["rule_id"] in ("C1", "C2", "C3")))
        case["severity"], case["title"] = best["severity"], best["title"]
        if case["status"] in CLOSED:
            case["status"] = "new"
            case["history"].append({"ts": iso(time.time()), "who": "system", "event": f"Reopened: new alert {a['alert_id']} ({a['rule_id']})"})
            self._mirror(case)
        return case

    def _mirror(self, case: dict) -> None:
        for i in case["alert_ids"]:
            al = self.by_id(i)
            if al:
                al["status"] = case["status"]

    def update_case(self, case_id: str, status: str | None = None, owner: str | None = None,
                    note: str | None = None, actor: str = "analyst") -> dict | None:
        case = next((c for c in self.cases.values() if c["case_id"] == case_id), None)
        if not case:
            return None
        now = iso(time.time())
        if status and status in STATUSES and status != case["status"]:
            case["history"].append({"ts": now, "who": actor, "event": f"Status {case['status']} → {status}"})
            case["status"] = status
        if owner is not None and owner != (case["owner"] or ""):
            case["owner"] = owner or None
            case["history"].append({"ts": now, "who": actor, "event": f"Owner set to {owner or 'unassigned'}"})
        if note:
            case["notes"].append({"ts": now, "who": actor, "text": note})
            case["history"].append({"ts": now, "who": actor, "event": "Note added"})
        self._mirror(case)
        return case

    def by_id(self, alert_id: str) -> dict | None:
        return next((a for a in self.alerts if a["alert_id"] == alert_id), None)

    # ------------------------------------------------------------------------------ C1 chain
    def _chain(self, ev, ts, sess, fired) -> dict | None:
        inj = sess["injection_ts"]
        if inj is None or sess["chain_fired"] or ts - inj > C.CHAIN_WINDOW:
            return None
        followers = [a for a in fired if a["rule_id"] in ("D2", "D3", "D4", "D5", "D6", "D7") and SEV_RANK[a["severity"]] >= 2]
        egress = (ev["event_type"] == "network_egress"
                  and not host_in(ev["data"].get("dest_host"), C.ALLOWED_EGRESS_SUFFIXES))
        if not followers and not egress:
            return None
        sess["chain_fired"] = True
        stages = [self.by_id(i) for i in sess["alert_ids"]]
        stage_txt = " → ".join(f"[{a['rule_id']}] {a['title'][:70]}" for a in stages if a)
        if egress:
            stage_txt += f" → EGRESS to {ev['data']['dest_host']} ({ev['data'].get('bytes_out')} B)"
        al = make_alert(
            "C1", ev, "critical", "Agentic kill chain: untrusted content → privileged action"
            + (" → external egress" if egress else ""),
            stage_txt, "Declare an incident: isolate the host/runner, revoke every credential the session could read, "
            "preserve the session transcript, and hunt for the same injected content in other repos/issues.",
            ["AML.T0051.001", "AML.T0053", "AML.T0086", "T1567"], key="chain",
            signals=["injection followed by privileged action within "
                     + (f"{int(ts - inj)} s" if ts - inj < 120 else f"{int((ts - inj) / 60)} min")],
            stages=[a["alert_id"] for a in stages if a])
        return self._emit(al, sess)

    # ------------------------------------------------------------------------------ D8
    def _track_host(self, ev, ts, emitted) -> None:
        h = self.hosts.setdefault(ev["host"], {"last": ts, "first": ts, "hb": 0, "events": 0, "flag": None,
                                               "user": ev["user"], "agent": None, "last_event": ev["event_id"],
                                               "tamper": deque(maxlen=5), "gaps": [], "recent": deque(maxlen=40), "ip": None})
        if h["hb"] >= C.MIN_HEARTBEATS_TO_BASELINE and ts - h["last"] > C.GAP_SECONDS:
            h["gaps"].append({"from": iso(h["last"]), "to": iso(ts), "minutes": round((ts - h["last"]) / 60)})
        h["last"], h["user"], h["last_event"] = ts, ev["user"], ev["event_id"]
        h["events"] += 1
        if ev.get("agent"):
            h["agent"] = ev["agent"]
        if ev["event_type"] == "heartbeat":
            h["hb"] += 1
            if ev["data"].get("ip"):
                h["ip"] = ev["data"]["ip"]
        elif ev["event_type"] == "shell_command" and TAMPER_CMD.search(ev["data"].get("command", "")):
            h["tamper"].append((ts, ev["data"]["command"], ev["session_id"]))
            sess = self._session(ev["session_id"])
            a = self._emit(make_alert(
                "D8", ev, "high", "Command that disables or evades log shipping", snip(ev["data"]["command"]),
                "Verify with the user; if not explained, contain the host and treat any silence that follows as "
                "deliberate. Restore the shipper via MDM.",
                ["T1685"], key=f"tamper|{ev['host']}|{ts}", signals=["log-pipeline tamper command"]), sess)
            if a:
                emitted.append(a)

    def _silence_check(self, now: float) -> list[dict]:
        base = [h for h, s in self.hosts.items() if s["hb"] >= C.MIN_HEARTBEATS_TO_BASELINE and s["flag"] != s["last"]]
        stale = [h for h in base if now - self.hosts[h]["last"] > C.GAP_SECONDS]
        if not stale:
            return []
        outage = len(stale) == len(base) and len(base) >= 2
        if outage:
            first = min(stale, key=lambda x: self.hosts[x]["last"])
            last_seen = min(self.hosts[x]["last"] for x in stale)
            for x in stale:
                self.hosts[x]["flag"] = self.hosts[x]["last"]
            gap_min = (now - last_seen) / 60
            ev = {"ts": iso(now), "session_id": "host:*", "user": "multiple", "host": f"ALL ({len(stale)} sources)",
                  "repo": None, "agent": None, "event_id": self.hosts[first]["last_event"], "source": "log_shipper",
                  "event_type": "silence"}
            a = make_alert(
                "D8", ev, "medium", f"Telemetry pipeline outage: all {len(stale)} sources silent for {gap_min:.0f} min",
                f"No events from any host since {iso(last_seen)}. Hosts: {', '.join(sorted(stale))}",
                "Treat as a platform failure first (shipper/collector/network), but backfill and review the gap: "
                "an attacker could hide inside it. Alert the platform on-call.",
                ["T1685"], key=f"outage|{iso(last_seen)[:13]}", signals=["all sources silent simultaneously"], scope="host")
            e = self._emit(a, self._session("host:*"))
            return [e] if e else []
        out = []
        for h in stale:
            s = self.hosts[h]
            gap_min = (now - s["last"]) / 60
            s["flag"] = s["last"]
            ev = {"ts": iso(now), "session_id": f"host:{h}", "user": s["user"], "host": h, "repo": None,
                  "agent": s["agent"], "event_id": s["last_event"], "source": "log_shipper", "event_type": "silence"}
            tamper = [t for t in s["tamper"] if s["last"] - t[0] <= C.TAMPER_LOOKBACK]
            if tamper:
                ev["session_id"] = tamper[-1][2]          # same case as the tamper command
            sess = self._session(ev["session_id"])
            if tamper:
                a = make_alert(
                    "D8", ev, "critical", f"Telemetry from {h} stopped {gap_min:.0f} min after a log-evasion command",
                    f"Last event {iso(s['last'])}; preceded by: {tamper[-1][1]}",
                    "Assume deliberate blinding. Contain the host now (EDR network isolation), suspend the user's "
                    "agent tokens, and acquire the device for forensics.",
                    ["T1685"], key=f"silent|{h}|{s['last']}",
                    signals=["silence after tamper command", f"{gap_min:.0f} min gap"], scope="host")
            else:
                a = make_alert(
                    "D8", ev, "medium", f"Telemetry from {h} stopped ({gap_min:.0f} min) while other sources are reporting",
                    f"Last event {iso(s['last'])} from user {s['user']}; peers still active.",
                    "Contact the user / check device online state. Unexplained silence on a developer endpoint with "
                    "agent access is an escalation trigger after 30 min.",
                    ["T1685"], key=f"silent|{h}|{s['last']}", signals=["single-source silence"], scope="host")
            e = self._emit(a, sess)
            if e:
                out.append(e)
        return out

    def tick(self, wall_ts: float) -> list[dict]:
        """Wall-clock watchdog for LIVE ingestion: silence must be detectable when *no* events arrive."""
        return self._silence_check(wall_ts) if self.live else []

    # ------------------------------------------------------------------------------ views
    def now(self) -> float:
        return time.time() if self.live else self.clock

    def host_status(self, h: dict, now: float) -> str:
        gap = now - h["last"]
        tampered = any(h["last"] - t[0] <= C.TAMPER_LOOKBACK for t in h["tamper"])
        if gap > C.GAP_SECONDS or h["flag"] == h["last"]:
            return "silent — tamper suspected" if tampered else "silent"
        if gap > 2 * C.HEARTBEAT_INTERVAL:
            return "delayed"
        return "reporting"

    def sources_view(self) -> dict:
        now = self.now()
        hosts = []
        for name, h in sorted(self.hosts.items()):
            if h["hb"] < 1:
                continue
            hosts.append({"host": name, "user": h["user"], "agent": h["agent"], "status": self.host_status(h, now),
                          "last_reported": iso(h["last"]), "age_min": round((now - h["last"]) / 60, 1),
                          "events": h["events"], "gaps": h["gaps"][-3:]})
        feeds = []
        for src, f in sorted(self.feeds.items()):
            age = now - f["last"]
            status = "reporting" if age <= 1800 or src == "log_shipper" and age <= C.GAP_SECONDS else "idle >30 min"
            feeds.append({"feed": src, "description": FEED_INFO.get(src, "custom source"), "events": f["events"],
                          "last_reported": iso(f["last"]), "age_min": round(age / 60, 1), "status": status})
        counts = Counter(h["status"].split(" ")[0] for h in hosts)
        return {"as_of": iso(now) if now else None, "mode": "live (wall clock)" if self.live else "stream time",
                "hosts": hosts, "feeds": feeds,
                "summary": {"reporting": counts["reporting"], "delayed": counts["delayed"],
                            "silent": counts["silent"], "total": len(hosts)}}

    def stats(self) -> dict:
        by_cat = {c: 0 for c in RULES.values()}
        by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        real = [a for a in self.alerts if a["tier"] == "case"]
        for a in real:
            by_cat[a["category"]] += 1
            by_sev[a["severity"]] += 1
        active = [c for c in self.cases.values() if c["status"] not in CLOSED]
        pr = Counter(self.priority(c)["level"] for c in active)
        src = self.sources_view()["summary"]
        if pr["P1"]:
            posture = {"level": "critical", "label": "Incident response required",
                       "detail": f"{pr['P1']} P1 and {pr['P2']} P2 case(s) active."}
        elif pr["P2"]:
            posture = {"level": "high", "label": "Elevated", "detail": f"{pr['P2']} P2 case(s) active."}
        elif active:
            posture = {"level": "medium", "label": "Watch", "detail": f"{len(active)} lower-priority case(s) active."}
        else:
            posture = {"level": "ok", "label": "Normal", "detail": "No active cases."}
        if src["silent"]:
            posture["detail"] += f" {src['silent']} log source(s) silent."
        acts = Counter(r["action"] for a in real for r in a["response_actions"])
        return {
            "events_processed": self.events_processed, "alerts_total": len(real), "signals_total": len(self.alerts) - len(real),
            "alerts_open": sum(a["status"] not in CLOSED for a in real),
            "cases_total": len(self.cases), "cases_active": len(active), "priority": {k: pr[k] for k in ("P1", "P2", "P3", "P4")},
            "cases_by_status": dict(Counter(c["status"] for c in self.cases.values())),
            "by_category": by_cat, "by_severity": by_sev, "posture": posture, "telemetry": src,
            "frozen_sessions": sum(1 for s in self.sessions.values() if s["frozen"]),
            "hosts_monitored": sum(1 for s in self.hosts.values() if s["hb"] >= C.MIN_HEARTBEATS_TO_BASELINE),
            "responses": {"sessions_frozen": acts["freeze_agent_session"], "host_isolations": acts["isolate_host_network"],
                          "packages_blocked": acts["block_package"], "webhooks": acts["notify_webhook"],
                          "quarantine_entries": acts["write_quarantine_log"], "files_flagged": acts["flag_files"]},
        }

    # ------------------------------------------------------------------------------ priority
    def priority(self, case: dict) -> dict:
        """P1-P4 for the on-shift analyst. Severity says how bad the worst alert is; priority says how much it matters NOW,
        given corroboration, whether it actually happened, and what it touched. Every point is explained in `reasons`."""
        alerts = [a for a in (self.by_id(i) for i in case["alert_ids"]) if a]
        real = [a for a in alerts if a["tier"] == "case"] or alerts
        if not real:
            return {"level": "P4", "score": 0, "confidence": "low", "reasons": []}
        top = max(SEV_RANK[a["severity"]] for a in real)
        score, why = {4: 70, 3: 55, 2: 38, 1: 10}[top], [f"worst alert is {[k for k, v in SEV_RANK.items() if v == top][0]}"]
        rules = {a["rule_id"] for a in real}
        ev = [a["evidence"] for a in real]

        happened = (any(e.get("executed") for e in ev) or bool(rules & {"D9", "D10"}) or
                    any(a["rule_id"] == "D3" and a["evidence"].get("install_script") for a in real) or
                    any(a["rule_id"] == "D5" and a["evidence"].get("event_type") in ("api_call", "network_egress", "dns_query") for a in real))

        def add(n, text):
            nonlocal score
            score += n
            why.append(text)
        if rules & {"C1", "C2", "C3"}:
            add(12, "correlated: separate signals tell one story")
        srcs = {e.get("source") for e in ev if e.get("source")}
        if len(srcs) >= 2:
            add(8, f"seen by {len(srcs)} independent log sources")
        if happened:
            add(8, "it actually happened (executed / accepted), not just attempted")
        if any(e.get("approval") in ("auto-approved", "inside reverse shell") for e in ev):
            add(4, "no human approved it")
        if any("Exposed access key" in a["title"] for a in real):
            add(10, "a stolen credential is in use")
        if any(a["rule_id"] == "D2" and a["severity"] in ("high", "critical") for a in real):
            add(10, "a live credential is exposed")
        if any(e.get("pii_count") for e in ev):
            add(10, "customer data involved")
        if any(a["rule_id"] == "D6" and a["severity"] == "high" for a in real):
            add(8, "persistence that spreads to teammates")
        if any(a["rule_id"] == "D8" and "outage" in a["title"].lower() for a in real):
            add(15, "monitoring is blind on every source")
        if (case.get("repo") or "") in C.CRITICAL_REPOS or str(case.get("host") or "").startswith(C.CRITICAL_HOSTS):
            add(6, "touches a critical system (payments, ledger, risk engine or a CI runner)")
        if str(case.get("user") or "").startswith(C.THIRD_PARTY_USER_PREFIX):
            add(6, "third-party device")
        # Confidence = how well the telemetry proves it is real, independent of how bad it would be. Risk x confidence decides the level:
        # a severe but unproven alert (one source, only attempted, a human approved it) is P2 until corroborated, never P1.
        proof = sum([bool(rules & {"C1", "C2", "C3"}), len(srcs) >= 2,
                     happened,
                     any(e.get("approval") in ("auto-approved", "inside reverse shell") for e in ev) or any(e.get("confirmed_by") for e in ev)])
        confidence = "high" if proof >= 2 else "medium" if proof == 1 else "low"
        why.append(f"confidence {confidence} ({proof} of 4 proof points: correlated, 2+ sources, it happened, no human approval or EDR-confirmed)")
        level = "P1" if score >= 90 else "P2" if score >= 55 else "P3" if score >= 38 else "P4"
        if level == "P1" and confidence != "high":
            level = "P2"
            why.append("capped at P2 until corroborated (high risk but not yet proven)")
        if top == 4 and level in ("P3", "P4"):
            level = "P2"                       # a critical alert is never below P2
        return {"level": level, "score": score, "confidence": confidence, "reasons": why}

    # ------------------------------------------------------------------------------ agentic case briefing
    def _decisions(self, case: dict, alerts: list[dict]) -> list[dict]:
        """Human-in-the-loop items for this case: union over the rules that fired, highest-severity rule first."""
        alerts = [a for a in alerts if a["tier"] == "case"]
        order = sorted(alerts, key=lambda a: (-(a["rule_id"] in ("C1", "C2", "C3")), -SEV_RANK[a["severity"]]))
        keys: list[str] = []
        for a in order:
            for k in RULE_DECISIONS.get(a["rule_id"], []):
                if k not in keys:
                    keys.append(k)
        due = DECISION_DUE[PRIORITY_SEV[self.priority(case)["level"]]]
        out = []
        for k in keys:
            st = case["decisions"].get(k)
            out.append({"key": k, **DECISION_DEFS[k], "due": due, "status": st["status"] if st else "pending",
                        "by": st["by"] if st else None, "at": st["ts"] if st else None,
                        "note": st.get("note") if st else None})
        return out

    def decide(self, case_id: str, key: str, decision: str, actor: str = "analyst", note: str | None = None) -> dict | None:
        case = next((c for c in self.cases.values() if c["case_id"] == case_id), None)
        if not case:
            return None
        alerts = [a for a in (self.by_id(i) for i in case["alert_ids"]) if a]
        valid = {d["key"] for d in self._decisions(case, alerts)}
        if key not in valid or decision not in ("approved", "declined"):
            raise ValueError("unknown decision")
        now = iso(time.time())
        case["decisions"][key] = {"status": decision, "by": actor, "ts": now, "note": note}
        label = DECISION_DEFS[key]["action"]
        verb = "Approved (executed, simulated)" if decision == "approved" else "Declined"
        case["history"].append({"ts": now, "who": actor, "event": f"{verb}: {label}"})
        self.responder.record_approval({"ts": now, "case": case_id, "decision": key, "result": decision, "by": actor,
                                        "action": label, "executed": "simulated" if decision == "approved" else "no"})
        return case

    def _briefing(self, case: dict, alerts: list[dict], decisions: list[dict], why: dict | None = None) -> dict:
        alerts = sorted(alerts, key=lambda a: (a["ts"], a["alert_id"]))
        grouped: dict[str, dict] = {}   # one line per action type (the same freeze/quarantine repeats for every alert in a session)
        for a in alerts:
            for r in a["response_actions"]:
                g = grouped.setdefault(r["action"], {"ts": a["ts"], "action": r["action"], "label": ACTION_LABEL.get(r["action"], r["action"]),
                                                     "status": r["status"], "detail": r["detail"], "alert_ids": []})
                g["alert_ids"].append(a["alert_id"])
        auto = list(grouped.values())
        stages = []
        for a in alerts:
            stages.append({"ts": a["ts"], "alert_id": a["alert_id"], "rule_id": a["rule_id"], "severity": a["severity"],
                           "stage": STAGE.get(a["rule_id"], a["category"]), "what": a["title"],
                           "signals": a["evidence"].get("signals", [])[:4]})
        sources = sorted({a["evidence"].get("source") for a in alerts if a["evidence"].get("source")}
                         | {e["source"] for e in case.get("_tl", []) if e.get("flagged")})
        files = sorted({p for a in alerts for p in (a["evidence"].get("paths") or [])})
        pkgs = sorted({a["evidence"]["package"] for a in alerts if a["evidence"].get("package")})
        data = sorted({s for a in alerts for s in a["evidence"].get("signals", []) if s.startswith(("PII", "unapproved LLM"))})
        counts = {x["action"]: len(x["alert_ids"]) for x in auto}
        counts = Counter(counts)
        done = []
        if counts["freeze_agent_session"]: done.append("suspended the agent session and revoked its short-lived tokens")
        if counts["isolate_host_network"]: done.append("requested EDR network isolation of the host")
        if counts["block_package"]: done.append("blocked the package in the registry")
        if counts["flag_files"]: done.append(f"flagged {len(files)} file(s) so they cannot be committed or merged")
        if counts["notify_webhook"]: done.append("paged the on-call channel")
        pending = [d for d in decisions if d["status"] == "pending"]
        t0, t1 = alerts[0]["ts"], alerts[-1]["ts"]
        chain = " → ".join(dict.fromkeys((["Untrusted content ingested"] if (why and why.get("link")) else []) + [s["stage"].split(":")[0] for s in stages if s["rule_id"] not in ("C1", "C2")]))
        first = alerts[0]
        scope = "a host-level event (no developer session)" if case["session_id"].startswith("host:") else \
            f"agent {first.get('agent') or '–'} working in {first.get('repo') or '–'}"
        summary = [
            f"{len(alerts)} detection(s) between {t0[11:19]}Z and {t1[11:19]}Z involving {first['user']} on {first['host']}, {scope}. Pattern: {chain}.",
            "Confirmed by " + (f"{len(sources)} independent log sources ({', '.join(sources)})." if len(sources) > 1 else f"one log source ({', '.join(sources) or 'n/a'}); corroborate before closing."),
        ]
        if why:
            summary.append("Cause: " + why["verdict"])
        if files or pkgs or data:
            summary.append("Exposed: " + "; ".join(x for x in [f"files {', '.join(files)}" if files else "",
                           f"package {', '.join(pkgs)}" if pkgs else "", f"{', '.join(data)}" if data else ""] if x) + ".")
        summary.append("Automation has already " + ", ".join(done) + "." if done else "Automation took no action (below response threshold).")
        summary.append(f"{len(pending)} decision(s) need a human {pending[0]['due']}: first: {pending[0]['action']}." if pending
                       else ("All recommended decisions have been made." if decisions else "No further human decision required."))
        story = ([{"ts": e["ts"], "kind": "event", "text": f"{e['type']}: {e['summary']}", "flagged": e["flagged"], "eid": e["event_id"],
                   "lane": LANES.get(e["type"], "Other")} for e in case.get("_tl", [])]
                 + [{"ts": a["ts"], "kind": "detection", "severity": a["severity"], "text": f"{a['alert_id']} [{a['rule_id']}] {a['title']}",
                     "eids": a["evidence"].get("event_ids", [])[:2], "lane": "Detections"} for a in alerts]
                 + [{"ts": x["ts"], "kind": "action", "text": x["label"], "lane": "Automation"} for x in auto if x["action"] not in ("notify_webhook", "write_quarantine_log")])
        rank = {"event": 0, "detection": 1, "action": 2}
        story.sort(key=lambda x: (x["ts"], rank[x["kind"]]))
        links = []
        if why and why.get("link"):
            links.append({"from": why["link"]["event_id"], "to": why["action"]["event_id"], "kind": "provenance"})
        shells = [r for r in story if r["kind"] == "event" and r.get("flagged")]
        for a_, b_ in zip(shells, shells[1:]):
            links.append({"from": a_["eid"], "to": b_["eid"], "kind": "followed"})
        return {"headline": f"{case['title']}", "summary": summary, "links": links, "stages": stages, "automated": auto, "story": story,
                "impact": {"user": first["user"], "host": first["host"], "repo": first.get("repo"), "files": files,
                           "packages": pkgs, "data": data, "sources": sources},
                "autonomy": {"automated": sum(len(x["alert_ids"]) for x in auto), "pending": len(pending), "decided": len(decisions) - len(pending)}}

    def case_view(self, case: dict, detail: bool = False) -> dict:
        out = {k: v for k, v in case.items() if k not in ("notes", "history", "decisions")}
        alerts = [a for a in (self.by_id(i) for i in case["alert_ids"]) if a]
        out["priority"] = self.priority(case)
        out["sla"] = SLA_TARGETS[PRIORITY_SEV[out["priority"]["level"]]]
        out["signals"] = sum(a["tier"] == "signal" for a in alerts)
        out["rules"] = sorted({a["rule_id"] for a in alerts})
        decisions = self._decisions(case, alerts)
        out["pending_decisions"] = sum(d["status"] == "pending" for d in decisions)
        out["auto_actions"] = sum(len(a["response_actions"]) for a in alerts)
        if detail:
            ids = {e for a in alerts for e in a.get("evidence", {}).get("event_ids", [])}
            sess = self.sessions.get(case["session_id"])
            if sess and sess["events"]:
                tl = list(sess["events"])
            elif case["session_id"].startswith("host:") and case["session_id"] != "host:*":
                tl = list(self.hosts.get(case["host"], {}).get("recent", []))[-15:]
            else:
                tl = []
            out["timeline"] = [{**e, "flagged": e["event_id"] in ids} for e in tl]
            out["notes"], out["history"] = case["notes"], case["history"]
            out["alerts"] = alerts
            out["decisions"] = decisions
            raw = list(sess["raw"]) if sess else []
            ctx = list(sess["ctx"]) if sess else []
            why = analyse_origin(alerts, raw, ctx) if alerts else None
            out["origin"] = why
            out["briefing"] = self._briefing({**case, "_tl": out["timeline"]}, alerts, decisions, why)
            out["summary"] = narrative.build(case, alerts, why, decisions, out["priority"])
            g = build_graph(case, alerts, raw, why["link"] if why else None) if alerts else {"nodes": [], "edges": [], "iocs": []}
            others = self._ioc_cases()
            for i in g["iocs"]:
                i["also_in"] = sorted(c for c in others.get(i["value"], set()) if c != case["case_id"])
            out["graph"] = g
            out["ai_reviews"] = self.ai_reviews.get(case["case_id"], [])
            out["ai_suggested"] = sorted({k for r in out["ai_reviews"] for k in r.get("proposed_actions", [])})
            if self.enricher:
                out["intel"] = self.enricher(case, alerts, g, sess)
                tags = {}
                for m in out["intel"]["matches"]:
                    tags.setdefault(m["matched"].lower(), []).append(f"{m['kind']}: {m['tag']}")
                for i in g["iocs"]:
                    i["intel"] = tags.get(str(i["value"]).lower(), [])
        return out

    def _ioc_cases(self) -> dict[str, set]:
        key = len(self.alerts)
        if getattr(self, "_ioc_cache", (None,))[0] == key:
            return self._ioc_cache[1]
        idx: dict[str, set] = defaultdict(set)
        for c in self.cases.values():
            sess = self.sessions.get(c["session_id"])
            alerts = [a for a in (self.by_id(i) for i in c["alert_ids"]) if a]
            if sess and alerts:
                for i in build_graph(c, alerts, list(sess["raw"]), None)["iocs"]:
                    idx[i["value"]].add(c["case_id"])
        self._ioc_cache = (key, idx)
        return idx

    def _params(self, rid: str) -> dict:
        from .detectors import SECRET_PATTERNS, SHELL_BEHAVIOURS, STRONG_INJ, WEAK_INJ
        P = {
            "D1": {"Strong signals (alert)": [n for n, _ in STRONG_INJ] + ["invisible / zero-width characters"], "Weak signals (never alert alone)": [n for n, _ in WEAK_INJ]},
            "D2": {"Secret formats": [x[0] for x in SECRET_PATTERNS] + ["name=value where the name ends in password/secret/token/key (entropy test)"],
                   "Placeholders ignored": ["example", "changeme", "${VAR}", "os.environ", "AKIA…EXAMPLE"], "Test / fixture paths": ["only well-known formats count"]},
            "D3": {"Internal package names": sorted(C.INTERNAL_PACKAGES), "Internal prefixes": list(C.INTERNAL_PREFIXES),
                   "Approved registries": list(C.INTERNAL_REGISTRY_HOSTS + C.PUBLIC_REGISTRY_HOSTS),
                   "Popular packages tracked (typosquat reference)": [f"{len(C.POPULAR_PACKAGES)} names"],
                   "Allow-listed look-alikes": sorted(C.LOOKALIKE_OK), "Known install-script packages": sorted(C.KNOWN_INSTALL_SCRIPTS),
                   "Thresholds": ["version ≥ 90 or install script = critical", "typosquat ≤ 2 edits and package younger than 180 days", "new package < 30 days with install script"]},
            "D4": {"Behaviours classified": SHELL_BEHAVIOURS, "Trusted vendor installers (lower severity)": list(C.TRUSTED_INSTALLERS),
                   "Never an alert": ["crontab -l", "cat *.pub", "rm -rf node_modules / dist / /tmp/*", "aws s3 ls", "human-approved sudo"]},
            "D5": {"Approved LLM endpoints (host or sub-domain)": sorted(C.APPROVED_LLM_HOSTS), "Exfil-risk services": list(C.EXFIL_SERVICE_SUFFIXES),
                   "Bulk-context rule": [f"≥ {C.BULK_CONTEXT_MIN_BYTES:,} B and > {C.BULK_CONTEXT_MULTIPLIER}× user baseline (≥ {C.BULK_CONTEXT_MIN_SAMPLES} samples)"],
                   "DNS tunnelling": [f"label ≥ {C.DNS_TUNNEL_LABEL_LEN} chars with high entropy, or ≥ {C.DNS_TUNNEL_BURST[0]} queries / {C.DNS_TUNNEL_BURST[1]} s to one domain"]},
            "D6": {"Agent config surfaces": list(C.AGENT_CONFIG_GLOBS), "Auto-run build and IDE files (attack signal only)": list(C.BUILD_HOOK_GLOBS),
                   "Approved MCP servers": sorted(C.APPROVED_MCP_SERVERS)},
            "D7": {"Protected branches (exact / glob)": list(C.PROTECTED_BRANCHES), "Organisation remotes": list(C.ORG_GIT_MARKERS)},
            "D8": {"Heartbeat interval": [f"{C.HEARTBEAT_INTERVAL} s"], "Silence gap": [f"{C.GAP_SECONDS} s"], "Beats needed to baseline": [str(C.MIN_HEARTBEATS_TO_BASELINE)],
                   "Tamper look-back": [f"{C.TAMPER_LOOKBACK // 60} min"]},
            "D9": {"Actions watched": sorted(C.SCM_CONTROL_WEAKENED) + ["repo.access → public"], "Join window to agent session": [f"{LINK_WINDOW // 60} min"]},
            "D10": {"Corporate source ranges": list(C.CORP_SOURCE_CIDRS), "Logging-off events": sorted(C.CLOUD_DEFENCE_EVASION),
                    "Permission-change events": sorted(C.CLOUD_PRIV_CHANGE), "Secret-read burst": [f"{C.SECRET_READ_BURST[0]}+ in {C.SECRET_READ_BURST[1] // 60} min"],
                    "Identities expected to read secrets": sorted(C.EXPECTED_SECRET_READERS)},
            "C1": {"Window after injection": [f"{C.CHAIN_WINDOW // 60} min"], "Follow-on rules": ["D2", "D3", "D4", "D5", "D6", "D7 (medium+)", "egress to a non-allowed host"]},
            "C2": {"Link strength": ["verbatim = critical", "indicator = high"], "Hosts ignored as indicators": list(C.ALLOWED_EGRESS_SUFFIXES)},
            "C3": {"Window": [f"{C.CHAIN_WINDOW // 60} min"], "Collection signals": ["credential file read", "PII / sensitive files in context", "credential committed"],
                   "Exit signals": ["D5 egress / DNS / unapproved LLM", "D7 push to foreign remote", "egress to a non-allowed host"]},
        }
        return P.get(rid, {})

    def rules_view(self) -> dict:
        hits = Counter(a["rule_id"] for a in self.alerts)
        tp, fp = Counter(), Counter()
        for c in self.cases.values():
            for rid in {self.by_id(i)["rule_id"] for i in c["alert_ids"] if self.by_id(i)}:
                if c["status"] == "closed_tp": tp[rid] += 1
                if c["status"] == "closed_fp": fp[rid] += 1
        rules = [{"id": k, "name": v["name"], "engine": ENGINE_TYPES[LOGIC[k]["engine"]], "engine_key": LOGIC[k]["engine"], **LOGIC[k],
                  "params": self._params(k), "hits": hits[k], "tp": tp[k], "fp": fp[k], "response": self._response_policy(k),
                  "decisions": [DECISION_DEFS[d]["action"] for d in RULE_DECISIONS.get(k, [])]} for k, v in RULE_CATALOG.items()]
        return {"summary": "Detection is deterministic: pattern rules, session and user correlation, and a baseline-plus-timer watchdog. No machine-learning or LLM model decides whether an alert fires.",
                "ownership": RULE_OWNERSHIP, "rules": rules, "capabilities": [{"name": n, "status": st, "note": t} for n, st, t in CAPABILITIES],
                "engine_types": ENGINE_TYPES}

    @staticmethod
    def _response_policy(rid: str) -> list[str]:
        return ["medium+: page on-call", "high/critical: quarantine register, suspend agent session, flag files"
                + (", block package" if rid == "D3" else "") + (", EDR host isolation (host-level)" if rid == "D8" else "")]

    def pipeline_view(self) -> dict:
        hits = Counter(a["rule_id"] for a in self.alerts)
        m = self.metrics
        return {
            "stages": {
                "collect": {"feeds": len(self.feeds), "by_source": dict(m["by_source"])},
                "parse": {"lines_received": m["lines_received"], "accepted": m["accepted"],
                          "rejected": dict(m["rejected"]), "truncated_fields": m["truncated"], "errors": m["errors"]},
                "normalise": {"sessions_tracked": len(self.sessions), "hosts_tracked": len(self.hosts),
                              "by_type": dict(m["by_type"]), "unclassified": m["unclassified"]},
                "detect": {"rules": sum(1 for k in RULE_CATALOG if not k.startswith("C")), "events_evaluated": m["accepted"] - m["by_type"]["heartbeat"],
                           "hits": dict(hits)},
                "correlate": {"kill_chains": hits["C1"], "provenance_links": hits["C2"], "collection_exfil": hits["C3"], "silence_alerts": hits["D8"],
                              "joined_to_session": self.metrics.get("joined", 0)},
                "case": {"alerts": sum(a["tier"] == "case" for a in self.alerts), "signals": sum(a["tier"] == "signal" for a in self.alerts), "cases": len(self.cases)},
            },
            "rules": [{"id": k, **v, "hits": hits[k]} for k, v in RULE_CATALOG.items()],
            "policies": {
                "Approved LLM endpoints (host or sub-domain)": sorted(C.APPROVED_LLM_HOSTS),
                "Egress allowlist (suffixes)": list(C.ALLOWED_EGRESS_SUFFIXES),
                "Exfil-risk services": list(C.EXFIL_SERVICE_SUFFIXES),
                "Internal package names / prefixes": sorted(C.INTERNAL_PACKAGES) + list(C.INTERNAL_PREFIXES),
                "Protected branches (exact / glob)": list(C.PROTECTED_BRANCHES),
                "Approved MCP servers": sorted(C.APPROVED_MCP_SERVERS),
                "Approved package registries": list(C.INTERNAL_REGISTRY_HOSTS + C.PUBLIC_REGISTRY_HOSTS),
                "Corporate source ranges (cloud/identity)": list(C.CORP_SOURCE_CIDRS),
                "Agent config surfaces": list(C.AGENT_CONFIG_GLOBS),
                "Auto-run build and IDE files (attack signal only)": list(C.BUILD_HOOK_GLOBS),
                "Register-backed lists (config/environment.json): entry · status · items": [
                    f"{k} · {v.get('status')} · {v.get('count')}" for k, v in C.ENV_REGISTER.items()],
                "Heartbeat interval / silence gap": [f"{C.HEARTBEAT_INTERVAL}s / {C.GAP_SECONDS}s"],
                "Kill-chain window": [f"{C.CHAIN_WINDOW // 60} min"],
            },
        }
