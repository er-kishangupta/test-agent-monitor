"""Platform and compliance view: what the monitor does about sign-in, encryption, retention, intel and AI, what is only an option, and what is
left to the production platform. The checks are computed from live settings; the 'considered' matrix is written down so that a gap is a decision
somebody can read, not something nobody noticed."""
from __future__ import annotations


from . import authn, netpolicy
from . import config as C
from .retention import Archive, checks as retention_checks, load_platform, policy_view

# status vocabulary: built = works and is tested here · option = setting or adapter exists, needs a service or tenant this prototype does not have
# · not built = left to the production platform (stated, with who provides it) · by design = deliberately not done
CONSIDERED = [
    ("Identity and access", "Staff sign-in through SSO (Microsoft Entra ID, AWS IAM Identity Center)", "option",
     "AUTH_MODE=proxy trusts identity headers from an identity-aware proxy and maps directory groups to roles. Tested with simulated headers. The OIDC redirect and token validation are the proxy's job and need a real tenant, so they are not built here."),
    ("Identity and access", "Directory groups mapped to analyst / senior / lead; no matching group = no access", "built", "config/platform.json group_to_role. Maker-checker then runs on a real identity instead of a typed name."),
    ("Identity and access", "MFA and conditional access", "not built", "Enforced by the identity provider in front of the proxy, not by the monitor."),
    ("Identity and access", "Per-jurisdiction data segregation (multi-tenancy)", "not built", "Provided by the production SIEM. Needed for data-residency rules across jurisdictions."),
    ("Identity and access", "Per-source ingest credentials or mutual TLS for log shippers", "not built", "The ingest endpoint shares the dashboard's sign-in. Production: one credential or client certificate per source, revocable."),
    ("Encryption", "TLS for the dashboard and API", "option", "app/serve.py serves HTTPS when TLS_CERT_FILE and TLS_KEY_FILE are set; REQUIRE_TLS=1 refuses plain HTTP; HSTS is sent over TLS. The demo runs plain HTTP on localhost."),
    ("Encryption", "Outbound endpoints (webhook, AI gateway, S3) must use https", "built", "app/netpolicy.py refuses http:// unless the target is loopback or ALLOW_INSECURE=1. Each exception is flagged here."),
    ("Encryption", "Archive encrypted at rest (AES-256-GCM per batch, key from the environment)", "built", "The archive refuses to write if encryption is required and no key exists. It never falls back to plain text."),
    ("Encryption", "Working files in out/ (alerts, audit log, intel list, cases) encrypted at rest", "not built", "Alert evidence is redacted before it is stored, but the files are plain JSON. Run the container on an encrypted volume (e.g. LUKS, EBS with KMS)."),
    ("Encryption", "Key management", "option", "Keys come from environment variables. Production: KMS or HSM, with rotation and separation of duties."),
    ("Retention and integrity", "Retention policy with hot, warm, total days, regulatory minimum, legal hold and residency", "built", "config/platform.json (baseline) plus the compliance checks below. The numbers are placeholders until Compliance confirms them."),
    ("Retention and integrity", "Edit and save retention and archive settings in the dashboard", "built", "Maker-checker: a different, more senior person approves, a lead if protection is weakened; refused if it would fail a compliance check; audited with before and after. Encryption, signing, keys, TLS and sign-in stay deploy-time. Demo state is memory-only unless PLATFORM_STATE_DIR is set."),
    ("Retention and integrity", "Hash-chained, signed archive manifest with verify", "built", "Each batch records the SHA-256 of its stored bytes, the previous record and an HMAC. Verify names the first broken record."),
    ("Retention and integrity", "Immutable (WORM) storage: S3 Object Lock in COMPLIANCE mode, SSE-KMS", "option", "Adapter written and unit-tested against a stub client. Not run against a real service: S3, KMS and Glacier are paid AWS services and need approval."),
    ("Retention and integrity", "Moving data between hot, warm and cold tiers; automatic expiry; restore", "not built", "Provided by the SIEM or data lake and by S3 lifecycle rules. This module checks the policy and archives."),
    ("Retention and integrity", "Event time normalised to UTC", "built", "All timestamps are UTC; silence detection runs on event time and on the wall clock."),
    ("Intel and enrichment", "Upload one list of IPs, ranges, domains, hosts and users for analyst context", "built", "Enrichment only: it never fires, suppresses or re-prioritises an alert. Rows expire. Every change is audited."),
    ("Intel and enrichment", "Network zones, assets and identities as context (CMDB, IPAM, HR/IAM style columns)", "built", "Zone, environment, address, OS, service, data held, department. An alert that names only an IP still finds the host. Loaded by upload today; the owner systems feed it in production."),
    ("Intel and enrichment", "Retro-hunt of the list over stored data", "built", "Searches what the monitor holds in memory. Production searches the SIEM's tiers."),
    ("Intel and enrichment", "Live threat-intel feeds (STIX/TAXII, MISP) and scheduled CMDB / IPAM / HR / IdP pulls", "not built", "Option for production: same columns and validation as the upload. Free public feeds have licence terms that Legal must check."),
    ("AI", "Detection and priority are deterministic; no model decides", "built", "A model reads attacker-controlled text and could be steered by it. See the Detection logic tab."),
    ("AI", "Optional AI second opinion through the bank's approved LLM gateway", "option", "Off by default. Approved-endpoint list under maker-checker, https only, data policy (tokenized by default), strict output, no authority, audited, rate-limited, kill switch. Built-in mock model is free; a real model is billed per call and needs approval."),
    ("AI", "Data minimisation before any AI call: policy tokenize (default), minimal, redact, or local_full for a bank-hosted model only", "built", "Credentials and customer identifiers (Emirates ID, IBAN, card) are removed and cannot be recovered; user, host, repo, e-mail and address names become tokens that only this monitor can reverse. A last check on the exact bytes refuses the call if anything is left. 'Preview what the AI would receive' on every case. Set at deploy time (AI_DATA_POLICY). Free-text customer names cannot be recognised by pattern: use minimal, or confirm the policy with the data-protection office."),
    ("AI", "Autonomous AI response (AI triggers containment on its own)", "by design", "Not built. It would repeat the confused-deputy problem this assessment is about. Safe next step: AI proposes, a named person approves."),
    ("Resilience", "High availability, backup and disaster recovery", "not built", "Single container with in-memory state. Provided by the production SIEM."),
    ("Resilience", "Scalable, buffered ingestion; rate limiting; web application firewall", "not built", "Production SIEM and the bank's perimeter. The prototype caps request and field sizes."),
    ("Resilience", "Secrets in a secret manager", "option", "Only environment variables here. No secret is stored in the repo or in config files."),
]


def _st(s: str) -> str:
    return {"ok": "pass", "mock": "pass", "warn": "warn", "unset": "pass", "refused": "fail"}.get(s, "warn")


def build(engine, register, intel_store, archive: Archive, assistant, audit, scheme: str = "http", mode: str | None = None) -> dict:
    cfg = load_platform()
    mode = mode or authn.mode()
    tls = netpolicy.tls_status()
    allow_ins = netpolicy.allow_insecure()
    ai = assistant.status()
    out = []

    def add(area, cid, title, status, detail):
        out.append({"area": area, "id": cid, "title": title, "status": status, "detail": detail})

    if mode == "proxy":
        ok = bool(authn.trusted_cidrs())
        add("Sign-in", "A1", "SSO through an identity-aware proxy", "pass" if ok else "fail",
            "headers accepted only from " + ", ".join(str(n) for n in authn.trusted_cidrs()) if ok else "AUTH_MODE=proxy but TRUSTED_PROXY_CIDRS is empty: every request is refused")
    elif mode == "basic":
        add("Sign-in", "A1", "Sign-in", "warn", "one shared password: keeps strangers out but identifies nobody. Maker-checker is enforced on a typed name. Production: AUTH_MODE=proxy")
    else:
        add("Sign-in", "A1", "Sign-in", "warn", "none: for local review only (compose binds to 127.0.0.1). Production: AUTH_MODE=proxy")
    served = tls["serving_tls"] or tls["behind_tls_proxy"]
    add("Transport", "T1", "Dashboard and API over TLS", "pass" if served else "warn",
        "TLS on" + (" (terminated at the proxy)" if tls["behind_tls_proxy"] and not tls["serving_tls"] else "") if served else "plain HTTP: demo only. Set TLS_CERT_FILE / TLS_KEY_FILE (see README) or terminate TLS at the proxy")
    add("Transport", "T2", "Plain-HTTP requests refused (REQUIRE_TLS)", "pass" if tls["require_tls"] else "warn", "on" if tls["require_tls"] else "off (demo)")
    for purpose, url in (("Alert webhook", C.WEBHOOK_URL), ("AI endpoint", ai["endpoint"] if ai["provider"] != "mock" else ""),
                         ("S3 archive endpoint", cfg.get("retention", {}).get("archive", {}).get("s3", {}).get("endpoint_url", "") if cfg.get("retention", {}).get("archive", {}).get("backend") == "s3" else "")):
        c = netpolicy.check_url(url, purpose)
        if c["status"] != "unset":
            add("Transport", "T3", f"{purpose} uses https", _st(c["status"]), c["detail"] + (f" ({c['url']})" if c["url"] not in ("", "mock") else ""))
    if allow_ins:
        add("Transport", "T4", "ALLOW_INSECURE is set", "warn", "plain-HTTP endpoints are tolerated. Remove for production")
    for c in retention_checks(cfg, archive.keys):
        add("Retention", c["id"], c["title"], c["status"], c["detail"])
    v = audit.verify()
    add("Audit", "U1", "Audit log hash chain intact", "pass" if v.get("ok") else "fail", f"{v.get('records', 0)} records" if v.get("ok") else str(v.get("reason")))
    av = archive.verify()
    add("Audit", "U2", "Archive manifest verifies", "pass" if av["ok"] else "fail", f"{av['records']} batch(es)" if av["ok"] else av.get("reason", ""))
    add("AI", "I1", "AI assistant", "pass", "off" if ai["mode"] == "off" else f"{ai['mode']} · provider {ai['provider']} · data policy {ai['data_policy']} ({ai['endpoint_scope']}) · {'ready' if ai['ready'] else '; '.join(ai['problems'])}")
    rv = register.view()["review"]
    add("Governance", "G1", "Register entries past their review-by date", "warn" if rv["expired"] else "pass", f"{rv['expired']} expired, {rv['due_soon']} due within 14 days")
    iv = intel_store.view()
    add("Governance", "G2", "Intel rows past their expiry", "warn" if iv["expired"] else "pass", f"{iv['expired']} expired of {iv['total']} (not matched any more)")
    summary = {s: sum(c["status"] == s for c in out) for s in ("pass", "warn", "fail")}
    counts: dict[str, int] = {}
    for _a, _t, st, _d in CONSIDERED:
        counts[st] = counts.get(st, 0) + 1
    return {"checks": out, "summary": summary, "considered": [{"area": a, "item": t, "status": st, "detail": d} for a, t, st, d in CONSIDERED], "considered_counts": counts,
            "auth": {"mode": mode, "trusted_proxy_cidrs": [str(n) for n in authn.trusted_cidrs()], "group_to_role": cfg.get("sso", {}).get("group_to_role", {}), "headers": {k: cfg.get("sso", {}).get(k) for k in ("user_header", "email_header", "groups_header")}},
            "tls": {**tls, "this_request": scheme, "allow_insecure": allow_ins}, "retention": policy_view(archive), "ai": ai, "request_scheme": scheme}
