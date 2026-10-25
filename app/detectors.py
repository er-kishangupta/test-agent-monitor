"""Detection rules (per-event). Cross-event logic (D8 silence, C1/C2/C3 correlation, containment checks) lives in engine.py.

Rules D1-D7 watch what the coding agent does (content in, commands, packages, LLM traffic, config, git).
Rules D9-D10 watch the control planes the agent's credentials can reach (source-control audit log, cloud audit log, identity).

Design principles
  * Detect on provenance + behaviour, not on prompt text alone.
  * Precision is a feature: a three-person SOC cannot triage noise. Every rule separates
    - an ALERT (medium and above: creates or joins a case a human must look at),
    - a SIGNAL (low: stored, searchable, attached to a case if one opens, never paged), and
    - nothing (routine developer activity: installers from the vendor, `crontab -l`, `rm -rf node_modules`).
  * Every rule is replayed against a corpus of realistic attack variants and benign look-alikes (app/validation.py)."""
from __future__ import annotations

import fnmatch
import hashlib
import ipaddress
import math
import re
import shlex

from . import config as C
from .mitre import RULES, mitre_block

# ----------------------------------------------------------------------------------- helpers
SECRET_PATTERNS = [
    # (label, regex, group holding the secret, extra filter)
    ("AWS access key ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), 0),
    ("AWS secret access key", re.compile(r"(?i)aws_?secret_?(?:access_?)?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"), 1),
    ("GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b"), 0),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), 0),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----"), 0),
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"), 0),
    ("LLM provider API key", re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}\b"), 0),
    ("Stripe live key", re.compile(r"\b[rs]k_live_[A-Za-z0-9]{16,}\b"), 0),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), 0),
    ("JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), 0),
    ("Azure storage key", re.compile(r"AccountKey=([A-Za-z0-9+/=]{40,})"), 1),
    ("Password inside a connection URL", re.compile(r"\b[a-z][a-z0-9+.-]{2,15}://[^\s:/@'\"<>]{1,64}:([^\s@/'\"<>]{6,})@([^\s'\"/:]+)"), 1),
]
# Name must END with a credential word (DB_PASSWORD, client_secret, apiKey) so auth_url / token_field / API_TOKEN_HEADER are ignored.
GENERIC_SECRET = re.compile(
    r"""(?im)\b[\w.-]*(?:api[_-]?key|apikey|secret|passw(?:or)?d|passwd|pwd|token|credential|access[_-]?key|private[_-]?key)["']?\s*[:=]\s*(?:"([^"\n]{10,})"|'([^'\n]{10,})'|([^\s"',;#]{10,}))""")
PLACEHOLDER = re.compile(r"(?i)(example|placeholder|changeme|change-me|your[_-]|<.+>|x{4,}|\*{4,}|dummy|sample|\$\{|%\(|\{\{|os\.environ|getenv|process\.env|vault:|secretsmanager)")
SAFE_URL_PASSWORDS = {"password", "pass", "postgres", "root", "admin", "secret", "changeme", "test", "dev", "user", "mysql", "redis"}
SAFE_URL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "db", "postgres", "mysql", "redis", "mongo"}
TEST_PATH = re.compile(r"(?i)(?:^|/)(?:tests?|__tests__|spec|fixtures?|mocks?|testdata|examples?|docs?)/|(?:^|[._-])(?:test|spec|mock|fake|fixture|sample)[._-]|\.(?:test|spec)\.\w+$")
SECRET_PATH = re.compile(
    r"(?:^|/)(?:\.env(?:\.(?!example$|sample$|template$|dist$|test$|ci$)[\w.-]+)?$|id_(?:rsa|dsa|ecdsa|ed25519)$|\.npmrc$|\.pypirc$|\.netrc$|"
    r"\.git-credentials$|\.vault-token$|kubeconfig$|\.docker/config\.json$|\.aws/credentials$|\.kube/config$|"
    r"[\w.-]*(?:priv|private|secret)[\w.-]*\.(?:pem|key)$|[\w.-]+\.(?:p12|pfx|jks|keystore|key)$)")
SOURCE_EXT = re.compile(r"(?i)\.(?:py|js|jsx|ts|tsx|java|kt|go|rb|rs|cs|php|swift|c|cc|cpp|h|hpp|sh|md|rst|txt|yml|yaml|toml|html|css|ipynb)$")
DATA_EXT = re.compile(r"(?i)\.(?:csv|tsv|xlsx|xls|parquet|sql|dump|bak|ndjson|jsonl|sqlite3?|db|zip|gz)$")
DATA_DIR = re.compile(r"(?i)(?:^|/)(?:exports?|dumps?|backups?|prod|production|pii|statements?)(?:/|$)")
DATA_NAME = re.compile(r"(?i)(?:customer|client|account|kyc|statement|transaction|payee|beneficiar)")


class _SensitivePath:
    """Data files, not source files: 'src/customer/profile.py' and 'src/kyc/upload.py' are code; 'data/exports/customers.csv' is customer data."""
    def search(self, path: str):
        p = (path or "").replace("\\", "/")
        if SOURCE_EXT.search(p):
            return None
        if DATA_DIR.search(p) or (DATA_EXT.search(p) and DATA_NAME.search(p.rsplit("/", 1)[-1])) or re.search(r"(?i)\.(?:sql|dump|bak)$", p):
            return True
        return None


SENSITIVE_DATA_PATH = _SensitivePath()
EID = re.compile(r"(?<![\d-])784-(?:19|20)\d{2}-\d{7}-\d(?![\d-])")
IBAN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")
CARD = re.compile(r"(?<![\d-])(?:\d[ -]?){13,19}(?![\d-])")
TEST_CARDS = {"4111111111111111", "4242424242424242", "5555555555554444", "378282246310005", "6011111111111117", "4012888888881881",
              "5105105105105100", "4000056655665556", "3530111333300000", "30569309025904", "4532015112830366", "2223003122003222"}
CARD_PREFIX = re.compile(r"^(?:4\d{12}(?:\d{3}){0,2}|5[1-5]\d{14}|2(?:2[2-9]|[3-6]\d|7[01])\d{13}|3[47]\d{13}|6(?:011|5\d{2})\d{12})$")
HIDDEN = re.compile("[​-‏⁠⁦-⁩\U000e0000-\U000e007f]")
URL = re.compile(r"https?://([A-Za-z0-9.-]+)")
IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def shannon(s: str) -> float:
    if not s:
        return 0.0
    return -sum((s.count(c) / len(s)) * math.log2(s.count(c) / len(s)) for c in set(s))


def luhn(num: str) -> bool:
    digits = [int(c) for c in num if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d = d * 2 - 9 if d * 2 > 9 else d * 2
        total += d
    return total % 10 == 0


def iban_ok(s: str) -> bool:
    """ISO 13616 mod-97 check: random look-alike strings almost never pass."""
    s = s.replace(" ", "").upper()
    if not 15 <= len(s) <= 34 or not s[:2].isalpha():
        return False
    moved = s[4:] + s[:4]
    try:
        return int("".join(str(int(c, 36)) for c in moved)) % 97 == 1
    except ValueError:
        return False


def _classes(v: str) -> int:
    return sum(bool(x) for x in (re.search(r"[a-z]", v), re.search(r"[A-Z]", v), re.search(r"\d", v), re.search(r"[^A-Za-z0-9\s]", v)))


def _generic_value_ok(v: str, line: str) -> bool:
    if PLACEHOLDER.search(v) or PLACEHOLDER.search(line):
        return False
    if re.match(r"(?i)^(?:https?|file|s3|gs)://", v) and "@" not in v:       # a URL, not a credential
        return False
    if v.startswith(("/", "./", "../", "~")) or re.fullmatch(r"[a-z]+(?:[_.-][a-z]+)*", v, re.I):   # path or identifier
        return False
    return _classes(v) >= 2 and shannon(v) >= 3.0


def find_secrets(text: str, formats_only: bool = False) -> list[tuple[str, str]]:
    """Return (label, secret value). `formats_only` skips the generic name=value heuristic (used for test files)."""
    text = text or ""
    hits: list[tuple[str, str]] = []
    for label, rx, grp in SECRET_PATTERNS:
        for m in rx.finditer(text):
            val = m.group(grp)
            if label == "AWS access key ID" and "EXAMPLE" in val.upper():
                continue
            if label == "Password inside a connection URL":
                host = m.group(2).lower()
                if val.lower() in SAFE_URL_PASSWORDS or host in SAFE_URL_HOSTS or PLACEHOLDER.search(val):
                    continue
            if label == "AWS secret access key" and PLACEHOLDER.search(val):
                continue
            hits.append((label, val))
    if not formats_only:
        for line in text.splitlines():
            for m in GENERIC_SECRET.finditer(line):
                val = next(g for g in m.groups() if g)
                if _generic_value_ok(val, line) and not any(val == h[1] for h in hits):
                    hits.append(("Hard-coded credential", val))
    return hits


def find_pii(text: str) -> list[tuple[str, str]]:
    text = text or ""
    hits = [("Emirates ID", m.group(0)) for m in EID.finditer(text)]
    hits += [("IBAN", m.group(0)) for m in IBAN.finditer(text) if iban_ok(m.group(0))]
    stripped = EID.sub(" ", text)
    for m in CARD.finditer(stripped):
        digits = re.sub(r"\D", "", m.group(0))
        if luhn(digits) and CARD_PREFIX.match(digits) and digits not in TEST_CARDS:
            hits.append(("Payment card (Luhn-valid)", m.group(0).strip()))
    return hits


def redact(text: str) -> str:
    """Mask secrets/PII in evidence so the alert store never becomes a secret store."""
    text = text or ""
    for _, val in find_secrets(text) + find_pii(text):
        text = text.replace(val, val[:4] + "…[REDACTED]")
    return text


def snip(text: str, n: int = 360) -> str:
    text = redact(text).replace("\n", " ⏎ ")
    return text if len(text) <= n else text[: n - 1] + "…"


def host_in(host: str, suffixes) -> bool:
    host = (host or "").lower()
    return any(host == s or host.endswith("." + s) for s in suffixes)


def is_org_remote(url: str) -> bool:
    return any(m in (url or "") for m in C.ORG_GIT_MARKERS)


# Explicit on purpose: Python treats documentation ranges (192.0.2/24, 198.51.100/24, 203.0.113/24) as "not global", which would
# silently make every sample attacker address look internal.
_INTERNAL = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10", "::1/128", "fc00::/7")]


def is_private_ip(host: str) -> bool:
    try:
        a = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(a in n for n in _INTERNAL)


def in_corp_range(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return is_private_ip(ip) or any(a in ipaddress.ip_network(c) for c in C.CORP_SOURCE_CIDRS)


def levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def hash_id(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def protected(branch: str) -> bool:
    b = (branch or "").removeprefix("refs/heads/")
    return any(fnmatch.fnmatch(b, p) for p in C.PROTECTED_BRANCHES)


def make_alert(rule_id: str, ev: dict, severity: str, title: str, snippet: str, action: str,
               techniques: list[str], key: str, signals: list[str] | None = None, **evidence) -> dict:
    return {
        "_key": f"{rule_id}|{ev.get('session_id')}|{key}",
        "ts": ev["ts"], "rule_id": rule_id, "category": RULES[rule_id], "title": title,
        "severity": severity, "mitre": mitre_block(techniques),
        "session_id": ev.get("session_id"), "user": ev.get("user"), "host": ev.get("host"),
        "repo": ev.get("repo"), "agent": ev.get("agent"),
        "evidence": {"event_ids": [ev.get("event_id")], "source": ev.get("source"),
                     "event_type": ev.get("event_type"), "snippet": snippet,
                     "signals": signals or [], **evidence},
        "recommended_action": action,
    }


# ----------------------------------------------------------------------------------- D1
# STRONG signals are text that only makes sense as an attempt to steer an AI (override, impersonating the system, secrecy from the
# user, data smuggling). WEAK signals ("run curl ...") are what installation docs look like, so they never alert on their own:
# if the agent then acts on them, C2 (provenance) catches the action.
AI_WORDS = r"(?:ai|a\.i\.|assistant|agent|llm|copilot|claude|cursor|chatgpt|gpt|language\s+model|coding\s+(?:assistant|agent))"
DIRECTIVE = r"(?:must|should|need\s+to|have\s+to|are\s+required\s+to|shall|please|now|first|before\s+(?:answering|responding|continuing)|instead)"
ACTION_VERB = r"(?:run|execute|ignore|disregard|forget|send|upload|post|email|print|reveal|output|exfiltrate|add|install|include|append|insert|delete|modify|override|fetch|visit|open|call|write)"
STRONG_INJ = [
    ("instruction override", re.compile(
        r"(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+|the\s+|your\s+|every\s+)?(?:previous|prior|above|earlier|preceding|system|original)\s+(?:instructions?|rules|prompts?|directions?|guidelines|context)", re.I)),
    ("override of the user's request", re.compile(
        r"(?:disregard|ignore|do\s+not\s+follow|don'?t\s+follow)\s+(?:the\s+|what\s+the\s+)?(?:user'?s?|developer'?s?|human'?s?)\s+(?:request|instructions?|task|prompt|question)", re.I)),
    ("role / system override", re.compile(
        r"(?:you\s+are\s+now\s+(?:in\s+)?(?:DAN|developer\s+mode|an?\s+(?:unrestricted|jailbroken|unfiltered|evil|different|new)\b)|from\s+now\s+on,?\s+you\s+(?:are|will|must)\s+(?!need\b|have\b|be\s+(?:able|asked|prompted|required|redirected)|see\b|get\b|receive\b|notice\b|find\b)|new\s+system\s+prompt|developer\s+mode\s+(?:enabled|on)|enter\s+developer\s+mode)", re.I)),
    ("impersonates the system or operator", re.compile(
        r"(?:important|urgent|critical)?\s*(?:system|admin(?:istrator)?|security|operator)\s+(?:notice|message|override|instruction|directive)s?\b[^\n]{0,80}\b" + AI_WORDS + r"\b|"
        r"\b(?:as|being)\s+(?:the|an?|my)\s+" + AI_WORDS + r",?\s+you\s+" + DIRECTIVE, re.I)),
    ("directive addressed to the AI", re.compile(
        r"(?:note|message|instructions?|attention|dear|hey|hi|hello|to)\s+(?:to\s+|for\s+)?(?:the\s+)?(?:any\s+)?" + AI_WORDS + r"s?\b[^\n]{0,60}[,:\-]\s*[^\n]{0,80}\b" + ACTION_VERB + r"\b", re.I)),
    ("concealment from the user", re.compile(
        r"(?:do\s+not|don'?t|never|without)\s+(?:tell|telling|inform|informing|mention|mentioning|reveal|revealing|notify|notifying|alert|alerting|show|showing)\s+(?:the\s+|your\s+)?(?:user|human|developer|operator)\s*(?:about\s+)?(?:this|it|these|that|any\s+of)\b", re.I)),
    ("hidden HTML-comment directive", re.compile(
        r"<!--[^>]{0,500}?\b" + AI_WORDS + r"\b[^>]{0,500}?-->", re.I | re.S)),
    ("data smuggling through a rendered URL", re.compile(
        r"!\[[^\]]*\]\(https?://[^)\s]*(?:\{\{|\$\{|<|%7B)[^)]*\)|(?:append|include|add|encode)[^\n]{0,60}\b(?:to|in|into)\s+the\s+url\b", re.I)),
    ("instruction to reveal the system prompt", re.compile(
        r"(?:print|reveal|show|output|repeat|send|upload)\s+(?:your\s+|the\s+)?(?:system\s+prompt|hidden\s+instructions|initial\s+instructions)", re.I)),
]
WEAK_INJ = [
    ("command aimed at the agent", re.compile(
        r"(?:run|execute)\s+(?:the\s+following\s+)?(?:command|script)?\s*:?\s*`?(?:curl|wget|bash|sh|powershell)\b", re.I)),
]
EXEC_HINT = re.compile(r"\b(curl|wget|bash|powershell|eval|rm\s+-rf|nc\s)\b", re.I)
META_TEXT = re.compile(r"(?i)prompt[\s-]injection|jailbreak|red[\s-]?team|\battacks?\b|\battackers?\b(?!@)|e\.g\.|for example|example of|mitigat|\bassert\b|sanitiz|\btest_|unittest|\bowasp\b|vulnerab|security\s+(?:blog|advisory|research)")


def _quoted(text: str, span: tuple[int, int]) -> bool:
    before, after = text[max(0, span[0] - 3): span[0]], text[span[1]: span[1] + 3]
    return bool(re.search(r"['\"`]\s*$", before)) and bool(re.match(r"\s*['\"`]", after))


def d1_prompt_injection(ev, eng):
    t, d = ev["event_type"], ev["data"]
    if t == "tool_result" and d.get("origin_trust") == "untrusted":
        text, indirect = d.get("content", ""), True
    elif t == "file_read" and d.get("trust") == "external":
        text, indirect = d.get("content_snippet", ""), True
    elif t == "prompt":
        text, indirect = d.get("text", ""), False
    else:
        return []
    strong, spans = [], []
    for label, rx in STRONG_INJ:
        m = rx.search(text)
        if m:
            strong.append(label)
            spans.append(m.span())
    if HIDDEN.search(text):
        strong.append("invisible/zero-width characters")
    weak = [label for label, rx in WEAK_INJ if rx.search(text)]
    if not strong:
        return []                                   # weak signals alone are documentation, not an attack
    # Text that quotes an attack inside a test, an article or a security write-up is not an attack on this agent.
    quoted = bool(spans) and all(_quoted(text, s) for s in spans)
    meta = bool(META_TEXT.search(text)) and len(strong) == 1
    if indirect:
        if quoted or meta:
            return [make_alert(
                "D1", ev, "low", f"Injection-style wording quoted in fetched content ({d.get('tool') or d.get('path') or 'content'})", snip(text),
                "No action unless the agent later acts on it (C2 watches for that). Likely documentation, a test or a security article.",
                ["AML.T0051.001"], key=f"ind|{ev['event_id']}", signals=strong + ["quoted / educational context"])]
        sev = "high" if (len(strong) >= 2 or EXEC_HINT.search(text)) else "medium"
        origin = d.get("tool") or d.get("path") or "external content"
        return [make_alert(
            "D1", ev, sev, f"Indirect prompt injection in untrusted content ({origin})", snip(text),
            "Treat session as compromised: suspend the agent session, review every action after this event, "
            "and block the content source (issue/PR/page/MCP server).",
            ["AML.T0051.001", "T1059"], key=f"ind|{ev['event_id']}", signals=strong + weak)]
    sev = "medium" if len(strong) >= 2 else "low"
    return [make_alert(
        "D1", ev, sev, "Direct prompt-injection / jailbreak phrasing in user prompt", snip(text),
        "Review with the user; if repeated, treat as policy-evasion attempt and restrict the agent's tool permissions.",
        ["AML.T0051.000"], key=f"dir|{ev['event_id']}", signals=strong)]


# ----------------------------------------------------------------------------------- D2
def d2_secret_exposure(ev, eng):
    t, d = ev["event_type"], ev["data"]
    out = []
    if t == "file_read" and SECRET_PATH.search(d.get("path", "")):
        out.append(make_alert(
            "D2", ev, "low", f"Agent read credential file {d['path']}", d["path"],
            "Confirm the task required it. Prefer a secrets manager / scoped short-lived credentials for agents.",
            ["T1552.001", "AML.T0055"], key=f"read|{d['path']}", paths=[d["path"]], collected="credential file"))
        return out
    field = {"file_edit": "diff_added", "prompt": "text", "api_call": "context_sample", "shell_command": "command"}.get(t)
    if not field:
        return out
    text = d.get(field, "")
    path = d.get("path", "")
    test_file = bool(path and TEST_PATH.search(path))
    hits = find_secrets(text)
    if not hits:
        return out
    # Fixture / test files routinely hold fake credentials: only well-known token FORMATS count there.
    if test_file:
        hits = [h for h in hits if h[0] != "Hard-coded credential"]
        if not hits:
            return out
    labels = sorted({h[0] for h in hits})
    for label, val in hits:                      # remember AWS key IDs (hashed) so D10 can see the key being USED later
        if label == "AWS access key ID":
            eng.exposed_keys[hash_id(val)] = {"session": ev["session_id"], "ts": ev["ts"], "user": ev.get("user"), "where": t}
    where = {"file_edit": "code generated/written by the agent", "prompt": "a prompt sent to the LLM",
             "api_call": "LLM request context", "shell_command": "a shell command"}[t]
    out.append(make_alert(
        "D2", ev, "high", f"{', '.join(labels)} exposed in {where}", snip(text),
        "Revoke/rotate the credential now (assume exposed), remove it from the code/history, and replace with a "
        "secrets-manager reference. Enable pre-commit secret scanning.",
        ["T1552.001", "AML.T0055"] + (["AML.T0057"] if t in ("prompt", "api_call") else []),
        key=f"{t}|{labels}|{path}", signals=labels, kinds=labels, where=where,
        paths=[path] if path else []))
    return out


# ----------------------------------------------------------------------------------- D3
def _release_info(d: dict):
    ver = d.get("version", "0")
    major = int(re.match(r"\d+", ver).group(0)) if re.match(r"\d+", ver) else 0
    return ver, major


def d3_supply_chain(ev, eng):
    if ev["event_type"] == "shell_command":
        return _d3_shell(ev)
    if ev["event_type"] != "package_install":
        return []
    d = ev["data"]
    name = d["package"].lower()
    registry = d.get("registry", "public")
    exists = d.get("exists_in_registry", True)
    age = d.get("publish_age_days", 9999)                  # age of THIS version
    pkg_age = d.get("first_published_days")                # age of the package itself (registry metadata), when the collector has it
    script = d.get("install_script", False)
    ver, major = _release_info(d)
    ident = f"{d.get('manager')} install {d['package']}@{ver} from {registry} registry (version {age}d old{'' if pkg_age is None else f', package {pkg_age}d old'}, install-script={script})"
    listed = name in C.INTERNAL_PACKAGES
    prefixed = name.startswith(C.INTERNAL_PREFIXES)
    base = dict(package=d["package"], version=ver, registry=registry, install_script=script)
    if registry == "public" and (listed or prefixed) and exists:
        sev = "critical" if (major >= 90 or script) else ("high" if listed else "medium")
        if sev == "medium" and pkg_age is not None and pkg_age >= 365:       # prefix-only match on an established public package
            return [make_alert("D3", ev, "low", f"Public package '{d['package']}' shares the internal naming prefix", ident,
                               "Probably unrelated (long-lived public package, no install script). Confirm it is not an internal name.",
                               ["T1195.001"], key=f"conf|{name}", signals=["name matches an internal prefix", "old public package"], **base)]
        return [make_alert("D3", ev, sev, f"Dependency confusion: internal package name '{d['package']}' resolved from PUBLIC registry",
                           ident, "Block the install, pin the internal registry scope (@nb/*) in .npmrc/pip.conf, "
                           "quarantine the CI job and rotate secrets exposed to it.",
                           ["T1195.001"], key=f"conf|{name}", signals=["internal name on public registry"] + (["name matches an internal prefix, not a known package"] if not listed else []), **base)]
    if not exists:
        return [make_alert("D3", ev, "medium", f"Agent suggested non-existent package '{d['package']}' (hallucinated dependency)",
                           ident, "Do not retry the install. Verify the intended library; attackers register hallucinated names "
                           "('slopsquatting'). Add to the agent's package denylist.",
                           ["T1195.001", "AML.T0060"], key=f"hall|{name}", signals=["package not found in registry"], **base)]
    if registry == "public" and name not in C.POPULAR_PACKAGES and name not in C.LOOKALIKE_OK and len(name) >= 5:
        near = [(levenshtein(name, p), p) for p in C.POPULAR_PACKAGES if abs(len(p) - len(name)) <= 2 and len(p) >= 5]
        near = sorted(n for n in near if 0 < n[0] <= 2)
        if near:
            young = (pkg_age is not None and pkg_age < 180) or (pkg_age is None and age < 30)
            established = pkg_age is not None and pkg_age >= 365
            if script and young:
                sev = "critical" if (pkg_age if pkg_age is not None else age) < 14 else "high"
            elif young and not established:
                sev = "high"
            elif established:
                return []
            else:
                return [make_alert("D3", ev, "low", f"Name resembles popular package '{near[0][1]}': {d['package']}", ident,
                                   "Probably legitimate (long-lived, no install script). Check only if unexpected.",
                                   ["T1195.001"], key=f"typo|{name}", signals=[f"lookalike of {near[0][1]}", "old package, no install script"], **base)]
            return [make_alert("D3", ev, sev, f"Typosquat: '{d['package']}' is {near[0][0]} edit(s) from popular package '{near[0][1]}'",
                               ident, "Block the install, replace with the intended package, and inspect the host for "
                               "install-script side effects.",
                               ["T1195.001"], key=f"typo|{name}", signals=[f"lookalike of {near[0][1]}"] + (["has install script"] if script else []), **base)]
        if script and name not in C.KNOWN_INSTALL_SCRIPTS:
            new_pkg = (pkg_age is not None and pkg_age < 30) or (pkg_age is None and age < 7)
            if new_pkg:
                return [make_alert("D3", ev, "medium", f"Brand-new package '{d['package']}' with install script",
                                   ident, "Manual review before allowing; require package age/provenance policy.",
                                   ["T1195.001"], key=f"new|{name}", signals=["new package + install script"], **base)]
    return []


INSTALL_FROM_URL = re.compile(r"\b(?:pip3?|python3?\s+-m\s+pip)\s+install\b[^\n|;&]*?(?:git\+|https?://)(\S+)|\bnpm\s+(?:i|install|add)\b[^\n|;&]*?(?:git\+|https?://|github:)(\S+)|\byarn\s+add\b[^\n|;&]*?(?:git\+|https?://|github:)(\S+)", re.I)
INDEX_OVERRIDE = re.compile(r"(?:--index-url|-i|--registry)[\s=]+(\S+)|npm\s+config\s+set\s+registry\s+(\S+)|pip3?\s+config\s+set\s+global\.index-url\s+(\S+)", re.I)
EXTRA_INDEX = re.compile(r"--extra-index-url[\s=]+(\S+)", re.I)


def _url_host(u: str) -> str:
    m = re.search(r"(?:https?://|git\+(?:ssh|https?)://|git@)([A-Za-z0-9.-]+)", u or "")
    return (m.group(1) if m else "").lower()


def _d3_shell(ev):
    cmd = ev["data"].get("command", "")
    if not re.search(r"\b(?:pip3?|npm|yarn|pnpm|python3?\s+-m\s+pip)\b", cmd):
        return []
    out = []
    m = INDEX_OVERRIDE.search(cmd)
    if m:
        url = next(g for g in m.groups() if g)
        host = _url_host(url) or url
        if not host_in(host, C.INTERNAL_REGISTRY_HOSTS + C.PUBLIC_REGISTRY_HOSTS):
            out.append(make_alert("D3", ev, "high", f"Package manager pointed at an unknown registry ({host})", snip(cmd),
                                  "Every install after this resolves from an attacker-controllable source. Revert the setting, block the host, and review what was installed since.",
                                  ["T1195.001"], key=f"idx|{host}", signals=["registry override", f"host {host} is not an approved registry"], package=host))
    m = EXTRA_INDEX.search(cmd)
    if m:
        host = _url_host(m.group(1)) or m.group(1)
        out.append(make_alert("D3", ev, "medium", f"--extra-index-url adds a second registry ({host}): dependency-confusion risk", snip(cmd),
                              "pip picks the highest version across all indexes: an attacker only has to publish your internal name there at a higher version. Use --index-url with a single proxy.",
                              ["T1195.001"], key=f"extra|{host}", signals=["extra index"], package=host))
    m = INSTALL_FROM_URL.search(cmd)
    if m:
        target = next(g for g in m.groups() if g)
        host = _url_host(cmd[m.start():]) or ""
        if host and not is_org_remote(cmd[m.start():]) and not host_in(host, C.INTERNAL_REGISTRY_HOSTS + C.PUBLIC_REGISTRY_HOSTS):
            external = not host_in(host, C.ALLOWED_EGRESS_SUFFIXES)
            out.append(make_alert("D3", ev, "high" if external else "medium", f"Dependency installed from a direct URL / repository outside the registry ({host})", snip(cmd),
                                  "Registry controls (age, provenance, scanning) are bypassed. Replace with a registry-hosted release or mirror the repository internally.",
                                  ["T1195.001"], key=f"url|{host}|{target[:60]}", signals=["install from URL/VCS", "host not on the registry allow-list" if external else "personal/other-org repository"], package=target[:80]))
    return out


# ----------------------------------------------------------------------------------- D4
REVERSE_SHELL = [
    re.compile(r"/dev/(?:tcp|udp)/", re.I),
    re.compile(r"\bn(?:c|cat|etcat)\b[^\n;|&]*?\s(?:-[a-zA-Z]*[ec]\b|--exec\b|--sh-exec\b)", re.I),
    re.compile(r"\bmkfifo\b[^\n]*\b(?:nc|ncat|telnet)\b", re.I),
    re.compile(r"\bsocat\b[^\n]*\b(?:exec|system)\s*:", re.I),
    re.compile(r"\bbash\s+-i\b[^\n]*>&"),
    re.compile(r"\bpython[23]?\b[^\n]*\bsocket\b[^\n]*(?:dup2|pty\.spawn|subprocess|/bin/(?:ba)?sh|os\.system)", re.I),
    re.compile(r"\b(?:perl|ruby|php|node|lua|awk|gawk)\b[^\n]*(?:socket|TCPSocket|fsockopen|net\.Socket|inet)[^\n]*(?:exec|/bin/(?:ba)?sh|spawn|system)", re.I),
    re.compile(r"\b(?:powershell|pwsh)\b[^\n]*(?:TCPClient|Net\.Sockets)", re.I),
    re.compile(r"\bopenssl\s+s_client\b[^\n]*\|\s*(?:/bin/)?(?:ba|z)?sh\b", re.I),
]
_SHELLS = r"(?:(?:/usr)?/bin/)?(?:(?:ba|z|da|k)?sh|python[23]?|perl|ruby|node)"
_FETCH = r"(?:curl|wget)"
PIPE_TO_SHELL = re.compile(_FETCH + r"\b[^\n|;]*\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:env\s+\S+=\S+\s+)?" + _SHELLS + r"\b", re.I)
SUBST_EXEC = [
    re.compile(r"\b(?:ba|z|da)?sh\s+<\(\s*" + _FETCH + r"\b", re.I),
    re.compile(r"\b(?:source|\.)\s+<\(\s*" + _FETCH + r"\b", re.I),
    re.compile(r"\b(?:ba|z|da)?sh\s+-c\s+[\"']?\$\(\s*" + _FETCH + r"\b", re.I),
    re.compile(r"\beval\s+[\"']?\$\(\s*" + _FETCH + r"\b", re.I),
    re.compile(r"\b(?:iex|Invoke-Expression)\b[^\n]*(?:iwr|Invoke-WebRequest|DownloadString|curl|wget|WebClient)", re.I),
    re.compile(r"\b(?:powershell|pwsh)\b[^\n]*\s-e(?:nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}", re.I),
    re.compile(r"\b(?:exec|eval)\s*\([^\n]*(?:urlopen|requests\.get|urllib\.request|\bfetch\s*\()", re.I),     # python/node: run code fetched in the same one-liner
]
DOWNLOAD_FILE = re.compile(_FETCH + r"\b[^\n]*?(?:\s-[a-zA-Z]*[oO]\s*\S+|\s>\s*\S+|--output\s+\S+)", re.I)
RUN_DOWNLOADED = re.compile(r"(?:&&|;)\s*(?:chmod\s+[+0-9a-z]+\s+\S+|(?:sudo\s+)?(?:ba|z)?sh\s+\S+|\./\S+|python[23]?\s+\S+|source\s+\S+)", re.I)
DECODE_TO_EXEC = [
    re.compile(r"(?:base64\s+(?:-d|--decode|-D)|openssl\s+(?:enc\s+)?base64\s+-d|xxd\s+-r)\b[^\n]*\|\s*(?:sudo\s+)?" + _SHELLS + r"\b", re.I),
    re.compile(r"(?:eval|(?:ba)?sh\s+-c)\s+[\"']?\$\([^)]*(?:base64\s+(?:-d|--decode)|xxd\s+-r)", re.I),
    re.compile(r"exec\(\s*(?:__import__\(\W*base64|base64\.b64decode|zlib\.decompress)", re.I),
]
SYSTEM_ROOTS = {"bin", "boot", "dev", "etc", "home", "lib", "lib32", "lib64", "opt", "proc", "root", "sbin", "srv", "sys", "usr", "var", "mnt", "media",
                "Users", "System", "Library", "Applications", "Volumes", "data", "db", "etc"}
SAFE_PREFIXES = ("/tmp/", "/var/tmp/", "/var/cache/", "/dev/shm/", "/var/log/journal/")
SAFE_BASENAMES = {"node_modules", "__pycache__", ".pytest_cache", "dist", "build", ".cache", ".venv", "venv", "target", ".next", "coverage", ".gradle", ".tox", ".mypy_cache"}
SENSITIVE_HOME_DIRS = {".ssh", ".aws", ".gnupg", ".kube", ".config"}
SENSITIVE_FILES = re.compile(r"(?:\.ssh/id_[a-z0-9]+(?!\.pub|[a-z0-9])|\.aws/credentials|\.kube/config|\.git-credentials|\.netrc|\.docker/config\.json|\.vault-token|\.config/gcloud/(?:credentials\.db|application_default_credentials\.json)|/etc/shadow|\.azure/(?:accessTokens|msal))")
# Whole-directory grabs (tar ~/.aws) count; merely USING a key (ssh -i ~/.ssh/id_ed25519) or listing a directory does not.
SENSITIVE_DIRS = re.compile(r"(?:~|\$HOME|\$\{HOME\}|/home/\w+|/Users/\w+)/\.(?:aws|ssh|kube|gnupg|azure)(?:/\s|/?\s|/?$|/\*)")
READ_VERB = re.compile(r"\b(?:cat|cp|scp|tar|zip|7z|base64|less|more|head|tail|xxd|strings|rsync|mv|gpg)\b|\bopenssl\s+(?:enc|base64)\b|\bcurl\b[^\n]*(?:=@|\s@|\s-T\s|--upload-file)|<\s*\S+|\b[Gg]et-[Cc]ontent\b|\bgc\b|-[Ii]n[Ff]ile\b")
NET_SINK = re.compile(r"\b(?:curl|wget|nc|ncat|netcat|scp|rsync|sftp|ftp|socat|telnet|http(?:ie)?)\b|/dev/tcp/|\bopenssl\s+s_client|requests\.(?:post|put)|\bgit\s+push|\binvoke-(?:webrequest|restmethod)\b|\b(?:iwr|irm)\b|\burlopen\b", re.I)
CLOUD_SECRET_CLI = re.compile(r"\baws\s+secretsmanager\s+get-secret-value|\baws\s+ssm\s+get-parameters?(?:-by-path)?\b[^\n]*--with-decryption|\bkubectl\s+get\s+secrets?\b|\bvault\s+(?:read|kv\s+get)\b|\bgcloud\s+secrets\s+versions\s+access|\baz\s+keyvault\s+secret\s+show", re.I)
CLOUD_PRIV_CLI = re.compile(
    r"\baws\s+iam\s+(?:create-access-key|create-user|create-login-profile|attach-(?:user|role|group)-policy|put-(?:user|role|group)-policy|update-assume-role-policy|add-user-to-group)|"
    r"\bgcloud\s+projects\s+add-iam-policy-binding|\baz\s+role\s+assignment\s+create|\bkubectl\s+create\s+(?:cluster)?rolebinding", re.I)
ACCOUNT_PERSIST = re.compile(r"\b(?:useradd|adduser|chpasswd)\b|\busermod\b[^\n]*-a?G\s*\w*(?:sudo|wheel|admin|docker)|\bvisudo\b|/etc/sudoers|NOPASSWD|chmod\s+[ugoa]*\+s\b|\bsetcap\b|\bpasswd\s+(?:root|\w+)\s*$", re.I)
ANTI_FORENSICS = re.compile(r"\bhistory\s+-c\b|unset\s+HISTFILE|HISTFILE=/dev/null|HISTSIZE=0|rm\s+[^\n]*(?:\.bash_history|\.zsh_history)|shred\b[^\n]*history", re.I)
CONTAINER_ESCAPE = re.compile(r"\bdocker\s+run\b[^\n]*(?:(?:-v|--volume)[\s=]+/:/|--pid[\s=]+host|--cap-add[\s=]+SYS_ADMIN)|\bnsenter\b[^\n]*-t\s*1\b|(?:-v|--volume)[\s=]+/var/run/docker\.sock", re.I)
DANGEROUS_OTHER = re.compile(
    r"\bdd\b[^\n]*\bof=/dev/(?:sd|nvme|vd|disk|hd)|\bmkfs(?:\.\w+)?\s|\bshred\s+-[a-z]*[uz]|:\(\)\s*\{\s*:\|:|\bchmod\s+(?:-R\s+)?[0-7]*777\s+(?:-R\s+)?/(?:\s|$)|"
    r"\bfind\s+/(?:\s|\S+\s)[^\n]*-delete|\bkubectl\s+delete\s+(?:ns|namespace|--all)|\bterraform\s+destroy\b|\baws\s+s3\s+rb\b|\baws\s+s3\s+rm\b[^\n]*--recursive|\baws\s+rds\s+delete-db|"
    r"\baws\s+ec2\s+terminate-instances|\b(?:psql|mysql|mariadb|sqlcmd|mongosh?)\b[^\n]*\b(?:DROP\s+(?:DATABASE|TABLE|SCHEMA)|TRUNCATE\s+TABLE)\b", re.I)
RC_FILES = r"(?:\.bashrc|\.bash_profile|\.zshrc|\.profile|/etc/profile(?:\.d/\S+)?)"
RC_RISKY = re.compile(r"\bcurl\b|\bwget\b|\bnc\b|\bncat\b|base64|\beval\b|/dev/tcp|bash\s+-i|python[23]?\s+-c|alias\s+(?:sudo|ssh|git|aws)=", re.I)


# .env files are normal to read and to cp; they matter when a network tool is in the same command and the destination is not trusted.
ENV_FILE = re.compile(r"(?:^|[\s/\\@=\"'(])\.env(?:\.(?!example\b|sample\b|template\b|dist\b)[\w-]+)?(?=$|[\s\"')|;&<>])", re.I)
# a one-line script that reads the environment or a credential file and calls out to the network
SCRIPT_RUNNER = re.compile(r"\b(?:python[23]?|node|ruby|perl|php|powershell|pwsh)(?:\.exe)?\b[^\n]*?\s-(?:c|e|r|command|enc|encodedcommand)\b", re.I)
SCRIPT_NET = re.compile(r"urlopen|urllib\.request|requests\.(?:post|put|get)|http\.client|httpx\.|\bfetch\s*\(|axios\.|XMLHttpRequest|net\.connect|invoke-webrequest|invoke-restmethod|\b(?:iwr|irm)\b|WebClient|UploadString|UploadFile|file_get_contents\s*\(\s*[\"']https?", re.I)
SCRIPT_SECRET = re.compile(r"os\.environ|os\.getenv|process\.env|\$env:|\bENV\[|getenv\(|open\(\s*[\"'][^\"']*(?:\.env|\.aws/credentials|id_rsa|\.netrc)|readFileSync\(\s*[\"'][^\"']*(?:\.env|\.aws|id_rsa)|[Gg]et-[Cc]ontent[^\n]*\.env|\.ssh/id_", re.I)
# Windows tools that download or run remote code without curl
WIN_LOLBIN_DL = re.compile(r"\bcertutil(?:\.exe)?\b[^\n]*-urlcache|\bbitsadmin\b[^\n]*/transfer", re.I)
WIN_DL = re.compile(r"\b(?:Start-BitsTransfer|certutil(?:\.exe)?|bitsadmin|(?:iwr|invoke-webrequest|curl\.exe)\b[^\n]*-(?:OutFile|o)\b)", re.I)
WIN_REMOTE_EXEC = re.compile(r"\bmshta(?:\.exe)?\s+https?://|\bregsvr32\b[^\n]*/i:https?://|\brundll32\b[^\n]*(?:https?://|\\\\\S+@)", re.I)
WIN_RUN = re.compile(r"(?:&&|;|&)\s*(?:start\s+|Start-Process\s+)?\S+\.(?:exe|bat|cmd|ps1|msi|dll)\b", re.I)


def _only_trusted_hosts(cmd: str) -> bool:
    hosts = URL.findall(cmd)
    if not hosts:
        return bool(re.search(r"\b(?:localhost|127\.0\.0\.1|\[::1\])\b", cmd))      # a bare localhost:8000 with no other host named
    return all(h in ("localhost", "127.0.0.1") or host_in(h, C.ALLOWED_EGRESS_SUFFIXES) for h in hosts)


SHELL_BEHAVIOURS = [
    "Reverse shell (nc / ncat / socat / bash /dev/tcp / python / perl / PowerShell)", "Remote script downloaded and executed (pipe, process substitution, download-then-run)",
    "Decoded payload executed", "Destructive delete of a system or home path (judged on the target)", "Destructive infrastructure command (dd, mkfs, DROP DATABASE, terraform destroy ...)",
    "SSH trust modification", "Shell start-up file modified to run code", "Scheduled job installed", "Credential file read / sent out", "Environment variables sent out",
    "File downloaded with a Windows system tool (certutil, bitsadmin)", "Script sends environment or credentials out",
    "Secret read through a cloud CLI", "Cloud identity or privilege change", "Local account or privilege persistence", "Container escape pattern", "Shell history wiped",
    "Privileged command run by the agent without approval",
]


def _segments(cmd: str):
    return [s.strip() for s in re.split(r"\s*(?:&&|\|\||;|\|)\s*", cmd) if s.strip()]


def destructive_rm(cmd: str) -> str | None:
    """Return the offending target when `rm -r` aims at a system root, a home directory itself or a protected area."""
    if re.search(r"--no-preserve-root", cmd):
        return "/"
    for seg in _segments(cmd):
        try:
            toks = shlex.split(seg, posix=True)
        except ValueError:
            toks = seg.split()
        while toks and toks[0] in ("sudo", "env", "nohup", "time", "command"):
            toks = toks[1:]
            while toks and toks[0].startswith("-"):
                toks = toks[1:]
        if not toks or toks[0] != "rm":
            continue
        flags = [t for t in toks[1:] if t.startswith("-")]
        recursive = any(f in ("--recursive",) or (not f.startswith("--") and ("r" in f or "R" in f)) for f in flags)
        if not recursive:
            continue
        for t in (x for x in toks[1:] if not x.startswith("-")):
            p = t.replace("${HOME}", "~").replace("$HOME", "~").rstrip()
            base = p.rstrip("/").split("/")[-1]
            if p in ("/", "/*", "~", "~/", "~/*", "~/.*") or p.startswith(("/*",)):
                return t
            if p.startswith("~/"):
                first = p[2:].split("/")[0]
                if first in SENSITIVE_HOME_DIRS and len(p[2:].split("/")) <= 2:
                    return t
                continue
            if p.startswith("/") and not p.startswith(SAFE_PREFIXES):
                root = p[1:].split("/")[0]
                if root in SYSTEM_ROOTS and base not in SAFE_BASENAMES:
                    return t
    return None


def _installer_trust(cmd: str) -> bool:
    m = re.search(r"https://([A-Za-z0-9.-]+)(/[^\s'\"|;)]*)?", cmd)
    if not m:
        return False
    host, path = m.group(1).lower(), (m.group(2) or "")
    for t in C.TRUSTED_INSTALLERS:
        th, _, tp = t.partition("/")
        if host == th and (not tp or path.startswith("/" + tp)):
            return True
    return False


def classify_command(cmd: str, approved_by: str | None = None, via_shell: bool = False) -> list[dict]:
    """Every behaviour the command exhibits: [{sev, label, techniques, why}]. The caller keeps the most severe."""
    hits: list[dict] = []
    auto = approved_by == "auto"
    nonhuman = auto or via_shell

    def add(sev, label, techs, why=None):
        hits.append({"sev": sev, "label": label, "techniques": techs, "why": why or label})

    if any(rx.search(cmd) for rx in REVERSE_SHELL):
        add("critical", "Reverse shell", ["T1059.004", "AML.T0053", "AML.T0072"], "opens an interactive shell to a remote host")
    remote = (PIPE_TO_SHELL.search(cmd) or any(rx.search(cmd) for rx in SUBST_EXEC) or (DOWNLOAD_FILE.search(cmd) and RUN_DOWNLOADED.search(cmd))
              or WIN_REMOTE_EXEC.search(cmd) or (WIN_DL.search(cmd) and WIN_RUN.search(cmd)))
    if remote:
        if _installer_trust(cmd):
            add("medium" if auto else "low", "Vendor installer piped into a shell", ["T1059.004", "T1105"], "downloads and runs a vendor installer (policy: use the internal mirror)")
        else:
            ip_literal = bool(re.search(r"https?://(?:\d{1,3}\.){3}\d{1,3}", cmd))
            add("critical" if (auto or ip_literal) else "high", "Remote script downloaded and executed", ["T1059.004", "AML.T0053", "T1105"], "runs code fetched from a host that is not a known installer")
    if WIN_LOLBIN_DL.search(cmd) and not remote:
        add("high", "File downloaded with a Windows system tool", ["T1105", "T1059", "AML.T0053"], "certutil / bitsadmin used as a downloader is a known evasion technique")
    if any(rx.search(cmd) for rx in DECODE_TO_EXEC):
        add("high", "Decoded payload executed", ["T1059.004", "AML.T0053"], "decodes an obfuscated payload and executes it")
    target = destructive_rm(cmd)
    if target:
        add("high", "Destructive delete of a system or home path", ["T1059.004", "AML.T0053", "T1485"], f"recursive delete of {target}")
    elif DANGEROUS_OTHER.search(cmd):
        add("high", "Destructive or irreversible infrastructure command", ["T1059.004", "AML.T0053", "T1485"], "wipes disks, databases or cloud resources")
    if re.search(r"authorized_keys|\bssh-copy-id\b", cmd) and re.search(r">>?|\btee\b|\bcp\b|\bmv\b|ssh-copy-id|\binstall\b", cmd):
        add("high", "SSH trust modification", ["T1059.004", "T1098.004"], "adds a key that grants persistent login")
    if re.search(r"(?:>>?|\btee\s+-a)\s*\S*" + RC_FILES, cmd) and RC_RISKY.search(cmd):
        add("high", "Shell start-up file modified to run code", ["T1059.004", "T1546"], "persistence through the login shell")
    if (re.search(r"\bcrontab\s+(?:-e\b|-\s*(?:$|[;&|)])|[^\s-]\S*\.\w+)", cmd) or re.search(r"\|\s*crontab\s+-", cmd) or re.search(r"/etc/cron\.|/var/spool/cron", cmd)) \
            and not re.search(r"\bcrontab\s+-[lr]\b", cmd.replace("| crontab -", "")):
        add("high" if RC_RISKY.search(cmd) else "medium", "Scheduled job installed", ["T1059.004", "T1053.003"], "creates a job that runs unattended")
    if re.search(r"\blaunchctl\s+(?:load|bootstrap)\b|\bschtasks\s+/create\b|reg\s+add\b[^\n]*\\Run\b", cmd, re.I):
        add("medium", "Start-up item installed", ["T1059.004"], "persistence")
    for seg in _segments(cmd):
        if (SENSITIVE_FILES.search(seg) or SENSITIVE_DIRS.search(seg)) and READ_VERB.search(seg):
            sink = NET_SINK.search(cmd)
            add("high" if sink else "medium", "Credential file sent out" if sink else "Credential file read by the agent",
                ["T1059.004", "AML.T0053", "T1552.001"], "the secret is " + ("transmitted" if sink else "now in the agent's context (and therefore the LLM provider's)"))
            break
    if not any(h["label"] == "Credential file sent out" for h in hits) and NET_SINK.search(cmd) and not _only_trusted_hosts(cmd) \
            and any(ENV_FILE.search(seg) and READ_VERB.search(seg) for seg in _segments(cmd)):
        add("high", "Credential file sent out", ["T1059.004", "AML.T0053", "T1552.001"], "a .env file (usually secrets) is sent to a host that is not trusted")
    if SCRIPT_RUNNER.search(cmd) and SCRIPT_NET.search(cmd) and SCRIPT_SECRET.search(cmd) and not _only_trusted_hosts(cmd):
        add("high", "Script sends environment or credentials out", ["T1059", "AML.T0053", "T1552.001", "T1048"], "a one-line script reads secrets and calls a host that is not trusted")
    if re.search(r"\b(?:printenv|env|set)\b\s*(?:\|\s*(?:base64|gzip)\s*)?\|\s*(?:curl|nc|ncat|wget)\b|\benv\b[^\n|]*\|\s*(?:curl|nc|wget)", cmd):
        add("high", "Environment variables sent out", ["T1059.004", "T1552.001"], "environment usually holds tokens")
    if CLOUD_SECRET_CLI.search(cmd):
        add("medium" if (auto or re.search(r"\bprod", cmd, re.I)) else "low", "Secret read through a cloud CLI", ["T1059.004", "AML.T0055"], "secret value enters the agent's context")
    if CLOUD_PRIV_CLI.search(cmd):
        add("high", "Cloud identity or privilege change via CLI", ["T1059.004", "AML.T0053", "T1098.001"], "creates credentials or widens permissions")
    if ACCOUNT_PERSIST.search(cmd):
        add("high", "Local account or privilege persistence", ["T1059.004", "T1136", "T1548.003"], "creates an account or grants standing privilege")
    if CONTAINER_ESCAPE.search(cmd) and approved_by != "pipeline":
        add("high", "Container escape / host takeover pattern", ["T1059.004", "T1611"], "mounts the host or shares its namespaces")
    if ANTI_FORENSICS.search(cmd):
        add("medium", "Shell history wiped", ["T1070.003"], "removes the trail of what ran")
    if re.match(r"^\s*sudo\s", cmd) and auto and not hits:
        add("medium", "Privileged command run by the agent without approval", ["T1059.004", "T1548.003"], "sudo with no human in the loop")
    return hits


def d4_unauthorized_shell(ev, eng):
    t, d = ev["event_type"], ev["data"]
    if t == "process_start":
        return _d4_process(ev, eng)
    if t != "shell_command":
        return []
    cmd = d.get("command", "")
    via = "reverse shell" in (d.get("parent_process") or "")
    hits = classify_command(cmd, d.get("approved_by"), via)
    if not hits:
        return []
    rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    top = max(hits, key=lambda h: rank[h["sev"]])
    auto = d.get("approved_by") == "auto"
    note = " (auto-approved by agent)" if auto else (" (executed inside a reverse shell, not by the agent)" if via else "")
    executed = None if d.get("exit_code") is None else d.get("exit_code") == 0
    approval = "auto-approved" if auto else ("inside reverse shell" if via else (d.get("approved_by") or "approval not recorded"))
    return [make_alert(
        "D4", ev, top["sev"], f"{top['label']}{note}", snip(cmd),
        "Suspend the agent session and isolate the host/runner if the command executed; collect shell audit "
        "log and process tree; remove auto-approve for this command class.",
        top["techniques"], key=f"{top['label']}|{cmd[:80]}",
        signals=[top["why"], approval] + [h["label"] for h in hits if h is not top],
        command=snip(cmd, 200), label=top["label"], approval=approval, executed=executed, initiator=d.get("initiator"))]


def _d4_process(ev, eng):
    d = ev["data"]
    img, cmdline = d.get("image", ""), d.get("cmdline", "")
    out = []
    if re.match(r"^(?:/tmp/|/var/tmp/|/dev/shm/|~?/\.cache/|C:\\Users\\[^\\]+\\AppData\\Local\\Temp\\)", img, re.I) and d.get("prevalence", 99) <= 1 \
            and not re.search(r"(?:^|/)(?:python[23]?|node|pip|npm|pytest|jest|go|cargo|rustc|gcc|cc|ld|make)$", img):
        installer_parent = bool(re.search(r"\b(?:npm|pip|yarn|pnpm|setup\.py|postinstall|preinstall)\b", d.get("parent_cmdline", "") or ""))
        out.append(make_alert(
            "D4", ev, "high" if installer_parent else "medium", "Never-seen binary executed from a temporary path" + (" by a package install script" if installer_parent else ""),
            snip(f"{img} {cmdline}"),
            "Hash the file, check it on VirusTotal-style reputation internally, and review the parent process chain. Quarantine the host if the hash is unknown.",
            ["T1059.004", "T1204.002"] + (["T1195.001"] if installer_parent else []), key=f"proc|{img}",
            signals=["image in temp path", f"seen on {d.get('prevalence', 0)} host(s) in the organisation"] + (["spawned by an install script"] if installer_parent else []),
            command=snip(f"{img} {cmdline}", 200), label="Never-seen binary from temp path", approval="n/a", executed=True))
    return out


# ----------------------------------------------------------------------------------- D5
BROWSERS = ("chrome", "firefox", "safari", "msedge", "edge", "brave", "slack", "discord", "teams")


def _is_scripting(proc: str) -> bool:
    p = (proc or "").lower().removesuffix(".exe")
    return p in C.SCRIPTING_PROCS or p.startswith(("python", "node"))


def d5_llm_exfil(ev, eng):
    t, d = ev["event_type"], ev["data"]
    out = []
    if t == "dns_query":
        return _d5_dns(ev, eng)
    if t == "network_egress":
        dest, proc, port = d.get("dest_host", ""), d.get("proc", ""), d.get("dest_port")
        if host_in(dest, C.EXFIL_SERVICE_SUFFIXES) and not (proc or "").lower().removesuffix(".exe").startswith(BROWSERS):
            out.append(make_alert(
                "D5", ev, "high", f"Agent-process egress to file/paste/tunnel service {dest}",
                f"{proc} -> {dest}:{port} ({d.get('bytes_out')} bytes)",
                "Block the destination at the egress proxy, suspend the session, and determine what data left.",
                ["T1567", "AML.T0057"], key=f"egress|{dest}", dest=dest, port=port, proc=proc, bytes=d.get("bytes_out")))
        elif IPV4_RE.match(dest or "") and not is_private_ip(dest) and _is_scripting(proc):
            odd = port not in C.RISKY_PORTS_OK
            out.append(make_alert(
                "D5", ev, "high" if odd else "medium",
                f"Shell/interpreter connected to a raw IP address{' on a non-standard port' if odd else ''} ({dest}:{port})",
                f"{proc} -> {dest}:{port} ({d.get('bytes_out')} bytes)",
                "Identify what the process is and who started it (EDR process tree). Raw-IP connections from a shell are typical of reverse shells and tooling downloads.",
                ["T1071", "AML.T0072"] if odd else ["T1071"], key=f"rawip|{dest}|{port}",
                signals=["raw IP, no DNS name"] + (["non-standard port"] if odd else []), dest=dest, port=port, proc=proc, bytes=d.get("bytes_out")))
        return out
    if t != "api_call":
        return out
    host = d.get("host", "")
    approved = host_in(host, C.APPROVED_LLM_HOSTS)
    pii = find_pii(d.get("context_sample", ""))
    pii_kinds = sorted({p[0] for p in pii})
    distinct = len({p[1] for p in pii})
    sens_files = [f for f in d.get("context_files", []) if SECRET_PATH.search(f) or SENSITIVE_DATA_PATH.search(f)]
    reasons = []
    if not approved:
        reasons.append(f"unapproved LLM endpoint {host}")
    if pii:
        reasons.append(f"PII in context: {', '.join(pii_kinds)} ({distinct} distinct value(s))")
    if sens_files:
        reasons.append("sensitive files in context: " + ", ".join(sens_files))
    hist = eng.user_bytes[ev["user"]]
    b = d.get("bytes_out", 0)
    if (len(hist) >= C.BULK_CONTEXT_MIN_SAMPLES and b >= C.BULK_CONTEXT_MIN_BYTES
            and b > C.BULK_CONTEXT_MULTIPLIER * (sum(hist) / len(hist))):
        reasons.append(f"bulk context {b/1e6:.1f} MB vs user baseline {sum(hist)/len(hist)/1e3:.0f} KB")
    hist.append(b)
    sensitive = bool(pii or sens_files or any(r.startswith("bulk") for r in reasons))
    if not approved and not sensitive:
        reasons = reasons[:1]                       # unapproved endpoint, nothing sensitive seen: still a policy breach
    if reasons and (not approved or sensitive):
        sev = "high" if (not approved or (pii and sens_files) or distinct >= 3) else "medium"
        out.append(make_alert(
            "D5", ev, sev, "Sensitive data sent as LLM context" + ("" if approved else " to an unapproved endpoint") if sensitive else f"Request to unapproved LLM endpoint {host}",
            snip(f"{host} model={d.get('model')} bytes={b} files={d.get('context_files')} sample={d.get('context_sample','')}"),
            "Block the endpoint/model, suspend the session, notify Data Protection (customer data may have left the "
            "approved boundary), and review gateway logs for the same user in the last 24h.",
            ["AML.T0057", "T1567"], key=f"llm|{ev['event_id']}", signals=reasons,
            paths=sens_files, host=host, approved_endpoint=approved, pii_kinds=pii_kinds, pii_count=distinct, collected="sensitive data" if sensitive else None))
    return out


def _entropy_label(q: str) -> tuple[int, float]:
    labels = (q or "").split(".")[:-2] or [""]
    longest = max(labels, key=len)
    return len(longest), shannon(longest)


def _d5_dns(ev, eng):
    d = ev["data"]
    q = (d.get("query") or "").lower().rstrip(".")
    if not q or host_in(q, C.DNS_TUNNEL_IGNORE):
        return []
    parent = ".".join(q.split(".")[-2:])
    out = []
    if host_in(q, C.EXFIL_SERVICE_SUFFIXES):
        out.append(make_alert("D5", ev, "medium", f"DNS lookup of file/paste/tunnel service {q}", f"{ev['host']} resolved {q}",
                              "Find the process behind the lookup (EDR) and check egress logs for the same host and time.",
                              ["T1567"], key=f"dns|{parent}", signals=["exfiltration-capable service"], dest=q))
    n, ent = _entropy_label(q)
    hist = eng.dns_hist[(ev["host"], parent)]
    hist.append(eng_ts(ev))
    win_n, win_s = C.DNS_TUNNEL_BURST
    burst = sum(1 for x in hist if hist[-1] - x <= win_s)
    if (n >= C.DNS_TUNNEL_LABEL_LEN and ent >= 3.2) or burst >= win_n:
        out.append(make_alert("D5", ev, "high", f"Possible DNS tunnelling to {parent}",
                              f"{ev['host']} {d.get('qtype', 'A')} {q[:90]}{'…' if len(q) > 90 else ''}  (longest label {n} chars, entropy {ent:.1f}; {burst} queries to {parent} in {win_s}s)",
                              "Data can leave the network inside DNS names even when HTTP egress is blocked. Identify the process, block the domain at the resolver, and review what that host could read.",
                              ["T1071.004", "T1572", "T1048"], key=f"tunnel|{parent}", signals=[f"label length {n}", f"entropy {ent:.1f}", f"{burst} queries/{win_s}s"], dest=parent))
    return out


def eng_ts(ev) -> float:
    from datetime import datetime
    return datetime.fromisoformat(ev["ts"].replace("Z", "+00:00")).timestamp()


# ----------------------------------------------------------------------------------- D6
HIGH_CONFIG = [
    ("concealment instruction", re.compile(r"(?i)(?:never|do\s+not|don'?t|without)\s+(?:mention|tell|reveal|disclose|inform|notify)[^.\n]{0,60}(?:user|developer|human|anyone|this)")),
    ("pipes a download into a shell", re.compile(r"(?i)\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b")),
    ("decodes and executes", re.compile(r"(?i)base64\s+(?:-d|--decode)|\beval\s*\(|\beval\s+\$\(|exec\(")),
    ("widens agent permissions to everything", re.compile(r"(?i)Bash\(\*\)|\"allow\"\s*:\s*\[[^\]]*\"\*\"|autoApprove\"?\s*[:=]\s*true|alwaysAllow|enableAllProjectMcpServers\"?\s*[:=]\s*true|dangerously|bypassPermissions|--yolo|allowedCommands\"?\s*[:=]\s*\[\s*\"\*\"")),
    ("untrusted pull request code runs with secrets", re.compile(r"(?is)pull_request_target.{0,600}(?:github\.event\.pull_request\.head|head\.sha|head\.ref)|permissions:\s*write-all")),
    ("asks the agent to send data out", re.compile(r"(?i)\b(?:send|post|upload|exfiltrate|forward|transmit)\b[^.\n]{0,80}https?://")),
    ("IDE auto-run / auto-approve setting", re.compile(r"(?i)task\.allowAutomaticTasks|chat\.tools\.\w*autoApprove|terminal\.integrated\.env")),
    ("dumps every CI secret", re.compile(r"(?i)toJSON\(\s*secrets\s*\)")),
    ("environment dumped and encoded", re.compile(r"(?i)\b(?:printenv|env)\b\s*\|\s*(?:base64|gzip|xxd|openssl)\b")),
]
# Auto-run build and IDE files: only a real attack signal counts (no natural-language rules, no "agent edited its own config" signal).
HIGH_BUILD = [
    ("IDE task runs automatically when the folder is opened", re.compile(r'(?i)"runOn"\s*:\s*"folderOpen"')),
    ("install or prepare hook fetches or runs remote or encoded code", re.compile(
        r'(?i)"(?:pre|post)?(?:install|prepare|prepack|publish)"\s*:\s*"[^"\n]*(?:https?://|\bcurl\b|\bwget\b|\bnc\b|base64|\beval\b|node\s+-e|powershell|\bsh\s+-c|\bbash\s+-c)')),
    ("container lifecycle command fetches code", re.compile(
        r'(?i)"(?:postCreateCommand|postStartCommand|onCreateCommand|postAttachCommand|initializeCommand|updateContentCommand)"\s*:\s*"[^"\n]*(?:https?://|\bcurl\b|\bwget\b|base64)')),
    ("decodes and executes", HIGH_CONFIG[2][1]),
]
MCP_SERVER_DEF = re.compile(r"\"([\w.@/-]+)\"\s*:\s*\{\s*\"(?:command|url|type|args|transport)\"")


def is_agent_config(path: str) -> bool:
    p = (path or "").replace("\\", "/")
    return any(fnmatch.fnmatch(p, g) or fnmatch.fnmatch(p, "*/" + g) for g in C.AGENT_CONFIG_GLOBS)


def is_build_hook(path: str) -> bool:
    p = (path or "").replace("\\", "/")
    return any(fnmatch.fnmatch(p, g) or fnmatch.fnmatch(p, "*/" + g) for g in C.BUILD_HOOK_GLOBS)


def d6_config_tampering(ev, eng):
    t, d = ev["event_type"], ev["data"]
    if t == "mcp_tool_call":
        approved = d.get("server_approved")
        if approved is None:
            approved = d.get("server") in C.APPROVED_MCP_SERVERS
        if approved:
            return []
        return [make_alert(
            "D6", ev, "high", f"Agent invoked tool on UNAPPROVED MCP server '{d.get('server')}'",
            f"{d.get('server')}.{d.get('tool')}({d.get('args_summary','')})",
            "Disable the MCP server in the agent config, review data passed to it, and add it to the MCP allowlist only after review.",
            ["AML.T0010.005", "AML.T0053"], key=f"mcp|{d.get('server')}", server=d.get("server"))]
    if t != "file_edit":
        return []
    path0 = d.get("path", "")
    build_only = is_build_hook(path0) and not is_agent_config(path0)
    if not (is_agent_config(path0) or build_only):
        return []
    text = d.get("diff_added", "")
    path = d["path"]
    by_agent = d.get("generated_by_agent", True)
    high = []
    if HIDDEN.search(text):
        high.append("invisible/zero-width characters in instructions")
    if build_only:
        high += [label for label, rx in HIGH_BUILD if rx.search(text)]
        if PIPE_TO_SHELL.search(text) or any(rx.search(text) for rx in SUBST_EXEC):
            high.append("pipes a download into a shell")
        if not high:
            return []
        return [make_alert(
            "D6", ev, "high", f"Auto-run file modified with an attack signal: {path}", snip(text),
            "Revert the change and diff against the last reviewed version. This file runs code when the folder is opened, a package is installed or a container "
            "starts, so check every developer and runner that pulled it. Require CODEOWNERS review for these files.",
            ["AML.T0081", "T1195.001", "T1059"], key=f"cfg|{path}", signals=sorted(set(high)), paths=[path], config_path=path)]
    high += [label for label, rx in HIGH_CONFIG if rx.search(text)]
    if "/workflows/" in "/" + path.replace("\\", "/") and re.search(r"\bsecrets\b", text) and re.search(r"\b(?:curl|wget|nc|Invoke-WebRequest|iwr)\b", text) \
            and any(not host_in(h, C.ALLOWED_EGRESS_SUFFIXES) for h in URL.findall(text)):
        high.append("sends a CI secret to a host outside the organisation")
    if path.endswith("mcp.json") or "mcpServers" in text:
        for name in MCP_SERVER_DEF.finditer(text):
            if name.group(1) not in C.APPROVED_MCP_SERVERS and name.group(1) != "mcpServers":
                high.append(f"adds MCP server '{name.group(1)}' that is not on the allow-list")
        if re.search(r"npx\s+-y\s+\S+@latest", text):
            high.append("MCP server launched from an unpinned package (@latest)")
    ext = sorted({h for h in URL.findall(text) if not host_in(h, C.ALLOWED_EGRESS_SUFFIXES)})
    if high:
        return [make_alert(
            "D6", ev, "high", f"Agent instruction/config file modified: {path}", snip(text),
            "Revert the change, diff against the last reviewed version, and require CODEOWNERS review for agent "
            "rule/MCP/CI files. Check other developers who pulled this branch.",
            ["AML.T0081", "T1195.001"], key=f"cfg|{path}", signals=high + ([f"external URL {h}" for h in ext[:2]] if ext else []), paths=[path], config_path=path)]
    if by_agent and (ext or path.endswith(("settings.local.json", "settings.json", ".cursorrules", ".windsurfrules", "CLAUDE.md", "AGENTS.md")) or "rules" in path):
        sig = ["agent edited its own configuration"] + ([f"external link {h}" for h in ext[:2]] if ext else [])
        return [make_alert(
            "D6", ev, "low", f"Agent edited its own instruction/config file: {path}", snip(text),
            "Routine in most cases (permissions the developer approved, style rules). Review in the pull request; no action needed unless the content looks wrong.",
            ["AML.T0081"], key=f"cfg|{path}", signals=sig, paths=[path], config_path=path)]
    return []


# ----------------------------------------------------------------------------------- D7
FORCE_FLAGS = re.compile(r"\bgit\s+push\b[^\n]*?(?:\s-f\b|\s--force(?:-with-lease)?\b(?!-)|\s\+\S+)")


def d7_git(ev, eng):
    t, d = ev["event_type"], ev["data"]
    out = []
    if t == "file_edit" and "/.git/hooks/" in "/" + d.get("path", "").replace("\\", "/"):
        out.append(make_alert("D7", ev, "high", f"Git hook written by agent: {d['path']}", snip(d.get("diff_added", "")),
                              "Remove the hook, inspect for command execution on commit/push, and re-clone the repo.",
                              ["T1059.004", "AML.T0081"], key=f"hook|{d['path']}", paths=[d["path"]]))
    if t == "shell_command":
        return _d7_shell(ev)
    if t != "git_op":
        return out
    op, branch = d.get("op"), d.get("branch", "")
    if op == "push" and d.get("force") and protected(branch):
        out.append(make_alert("D7", ev, "high", f"Force-push to protected branch '{branch}'",
                              snip(f"git push --force {d.get('remote')} {branch}"),
                              "Restore the branch from reflog/remote backup, enforce branch protection (no force-push, "
                              "required reviews) and check what history was rewritten.",
                              ["T1485", "AML.T0101"], key=f"force|{branch}", branch=branch))
    if op == "push" and d.get("remote_url") and not is_org_remote(d["remote_url"]):
        out.append(make_alert("D7", ev, "high", "Push to a repository outside the organisation",
                              snip(f"git push {d['remote_url']} {branch}"),
                              "Treat as data exfiltration: delete the remote copy if possible, suspend the session, "
                              "and determine which code/secrets were pushed.",
                              ["T1567.001", "AML.T0086"], key=f"remote|{d['remote_url']}", remote=d["remote_url"], collected="source code"))
    if op == "commit":
        bad = [f for f in d.get("files", []) if SECRET_PATH.search(f)]
        if bad:
            out.append(make_alert("D7", ev, "high", "Credential file staged in commit", snip(", ".join(bad)),
                                  "Unstage and purge from history before push; rotate the credentials it contained.",
                                  ["T1552.001", "AML.T0055"], key=f"commitsecret|{bad}", paths=bad))
    if d.get("no_verify"):
        out.append(make_alert("D7", ev, "low", f"Git hooks bypassed (--no-verify) on {op}", snip(f"git {op} --no-verify"),
                              "Common for work-in-progress commits. Matters only if secrets or unreviewed code reach a protected branch (server-side checks still apply).",
                              ["T1562.001"], key=f"noverify|{ev['event_id']}"))
    return out


def _d7_shell(ev):
    cmd = ev["data"].get("command", "")
    out = []
    if "git" not in cmd:
        return out
    m = FORCE_FLAGS.search(cmd)
    if m:
        tokens = [t for t in re.split(r"\s+", cmd[m.start():].split("&&")[0].split(";")[0]) if t and not t.startswith("-")]
        refs = [t.lstrip("+") for t in tokens[3:]] if len(tokens) > 3 else []
        branch = next((r.split(":")[-1] for r in refs if protected(r.split(":")[-1])), None)
        if branch:
            out.append(make_alert("D7", ev, "high", f"Force-push to protected branch '{branch}'", snip(cmd),
                                  "Restore the branch from reflog/remote backup, enforce branch protection (no force-push, required reviews) and check what history was rewritten.",
                                  ["T1485", "AML.T0101"], key=f"force|{branch}", branch=branch))
    for m in re.finditer(r"\bgit\s+(?:push|remote\s+(?:add|set-url))\b[^\n;&|]*?((?:https?://|ssh://|git@|git://)[^\s'\"]+)", cmd):
        url = m.group(1)
        if not is_org_remote(url):
            push = "push" in m.group(0)
            out.append(make_alert("D7", ev, "high" if push else "medium",
                                  "Push to a repository outside the organisation" if push else "Git remote outside the organisation configured",
                                  snip(cmd), "Treat a push as data exfiltration: delete the remote copy if possible, suspend the session, and determine which code/secrets were pushed."
                                  if push else "Verify why a non-org remote is needed; it is the first step of a repository copy-out.",
                                  ["T1567.001", "AML.T0086"], key=f"remote|{url}", remote=url, collected="source code" if push else None))
    if re.search(r"(?:>>?|\btee\b|\bcp\b|\bmv\b|\binstall\b|\bln\b)[^\n]*\.git/hooks/|git\s+config[^\n]*core\.hooksPath", cmd):
        out.append(make_alert("D7", ev, "high", "Git hook installed through the shell", snip(cmd),
                              "Remove the hook, inspect for command execution on commit/push, and re-clone the repo.",
                              ["T1059.004", "AML.T0081"], key=f"hook|{cmd[:60]}"))
    if re.search(r"\bgit\s+(?:commit|push)\b[^\n]*--no-verify", cmd):
        out.append(make_alert("D7", ev, "low", "Git hooks bypassed (--no-verify)", snip(cmd), "Common for work-in-progress commits; server-side checks still apply.",
                              ["T1562.001"], key=f"noverify|{ev['event_id']}"))
    return out


# ----------------------------------------------------------------------------------- D9  source-control control plane
def d9_scm_control(ev, eng):
    if ev["event_type"] != "audit_event":
        return []
    d = ev["data"]
    action = d.get("action", "")
    actor, repo = d.get("actor") or ev.get("user"), d.get("repo")
    api = (d.get("programmatic_access_type") or "").lower() not in ("", "web", "browser")
    in_agent = ev.get("_linked", False)
    sev_label = C.SCM_CONTROL_WEAKENED.get(action)
    out = []
    if action == "repo.access" and (d.get("visibility") == "public" or d.get("visibility_new") == "public"):
        sev_label = ("critical", "Repository made PUBLIC")
    if action in ("repo.add_member", "org.add_outside_collaborator") and d.get("is_external", False):
        sev_label = ("high", "External collaborator added")
    if action == "deploy_key.create" and d.get("read_only") is True:
        sev_label = ("low", "Read-only deploy key added")
    if action == "repo.add_member" and not d.get("is_external", False):
        sev_label = None
    if action == "oauth_authorization.create":
        scopes = d.get("scopes") or []
        broad = [s for s in scopes if s in ("repo", "admin:org", "workflow", "write:packages", "delete_repo", "admin:repo_hook")]
        sev_label = ("high", "OAuth app authorised with broad scopes") if broad else None
    if not sev_label:
        return []
    sev, label = sev_label
    if api and in_agent and sev == "medium":
        sev = "high"                                   # done with an API token while the developer's agent was working
    signals = [label, "done with an API token" if api else "done in the web UI"] + (["during an active agent session"] if in_agent else [])
    out.append(make_alert(
        "D9", ev, sev, f"{label}{f' on {repo}' if repo else ''} by {actor}", snip(f"{action} repo={repo} actor={actor} ip={d.get('actor_ip')} via={d.get('programmatic_access_type')} {d.get('scopes') or ''}"),
        "Confirm with the actor that they made this change. If an agent made it with the developer's token, revoke the token, restore the control (branch protection, visibility, secret scanning) and review what was pushed while it was off.",
        ["T1562.001", "AML.T0053"], key=f"scm|{action}|{repo}|{d.get('branch','')}", signals=signals,
        scm_action=action, repo_name=repo, actor=actor, actor_ip=d.get("actor_ip"), via=d.get("programmatic_access_type"), scm_label=label))
    return out


# ----------------------------------------------------------------------------------- D10  credential misuse (cloud + identity)
def d10_credential_misuse(ev, eng):
    t, d = ev["event_type"], ev["data"]
    if t == "cloud_api":
        return _d10_cloud(ev, eng)
    if t == "auth_event":
        return _d10_auth(ev, eng)
    return []


def _d10_cloud(ev, eng):
    d = ev["data"]
    name = d.get("eventName", "")
    ip = d.get("sourceIPAddress", "")
    ident = d.get("userIdentity", {}) or {}
    key_id = ident.get("accessKeyId") or ""
    who = ident.get("userName") or ident.get("arn") or ev.get("user")
    if ip.endswith(".amazonaws.com") or ip == "AWS Internal":
        return []
    corp = in_corp_range(ip)
    failed = bool(d.get("errorCode"))
    out = []
    common = dict(api_event=name, source_ip=ip, identity=who, access_key=("…" + key_id[-4:]) if key_id else None, failed=failed)
    exposed = eng.exposed_keys.get(hash_id(key_id)) if key_id else None
    if exposed:
        sev = "critical" if not corp else "high"
        out.append(make_alert(
            "D10", ev, sev, f"Exposed access key …{key_id[-4:]} was USED: {name} from {ip}{' (outside the corporate network)' if not corp else ''}",
            snip(f"{name} by {who} from {ip} ua={d.get('userAgent','')[:60]} err={d.get('errorCode') or '-'}"),
            "The key leaked by the agent is being used. Disable it now, review everything it did since the exposure (CloudTrail by key ID), and treat the developer's cloud account as compromised.",
            ["T1078.004", "T1552.001"], key=f"exposed|{key_id}|{name}", signals=["key previously exposed by this monitor", "source outside corporate ranges" if not corp else "source inside corporate ranges", "call failed" if failed else "call succeeded"],
            exposed_alert=exposed["session"], **common))
    if name in C.CLOUD_DEFENCE_EVASION:
        out.append(make_alert(
            "D10", ev, "critical" if not corp else "high", f"Cloud audit logging or detection disabled: {name} by {who}", snip(f"{name} by {who} from {ip}"),
            "Re-enable logging immediately and treat everything since as unobserved. Disable the calling credential.",
            ["T1562.008"], key=f"evade|{name}|{ip}", signals=["defence evasion in the cloud control plane"] + ([] if corp else ["external source"]), **common))
    elif name in C.CLOUD_PRIV_CHANGE and not exposed:
        out.append(make_alert(
            "D10", ev, "high", f"Cloud identity or permission change by a developer credential: {name}", snip(f"{name} by {who} from {ip}"),
            "Confirm with the developer. New access keys, policies or users created from a developer/agent credential are a persistence mechanism.",
            ["T1098.001", "T1136"], key=f"priv|{name}|{who}", signals=["privilege or credential change"] + ([] if corp else ["external source"]), **common))
    elif not exposed and not corp and not failed:
        if name in C.CLOUD_SECRET_READ or name in C.CLOUD_RECON or name.startswith(("List", "Describe", "Get")):
            sev = "high" if name in C.CLOUD_SECRET_READ else "medium"
            out.append(make_alert(
                "D10", ev, sev, f"Developer credential used from outside the corporate network: {name} from {ip}", snip(f"{name} by {who} from {ip} ua={d.get('userAgent','')[:60]}"),
                "Check whether the developer is travelling or off-VPN. If not, assume the credential is stolen: disable it and review its activity. A GetCallerIdentity call from a new address is the classic first move after theft.",
                ["T1078.004", "T1580"], key=f"extip|{who}|{ip}", signals=["source IP outside corporate ranges"], **common))
    if name in C.CLOUD_SECRET_READ and who not in C.EXPECTED_SECRET_READERS and ident.get("type") != "AssumedRole":
        n, win = C.SECRET_READ_BURST
        hist = eng.secret_reads[who]
        hist.append(eng_ts(ev))
        if sum(1 for x in hist if hist[-1] - x <= win) >= n:
            out.append(make_alert(
                "D10", ev, "high", f"Burst of secret reads by {who}: {n}+ in {win // 60} min", snip(f"{name} by {who} from {ip}"),
                "Bulk secret reads are credential harvesting. Disable the credential and list which secrets were returned (rotate them).",
                ["T1552.001", "T1530"], key=f"burst|{who}", signals=[f"{n}+ secret reads within {win}s"], **common))
    return out


def _d10_auth(ev, eng):
    d = ev["data"]
    user, tok = ev.get("user"), d.get("token_id")
    if d.get("outcome") != "success" or d.get("token_type") not in ("agent_token", "pat", "api_key"):
        return []
    out = []
    frozen = eng.frozen_users.get(user)
    issued = d.get("token_issued")
    if frozen and issued and issued <= frozen["iso"] and ev["ts"] > frozen["iso"]:
        out.append(make_alert(
            "D10", ev, "critical", f"Containment failed: token for {user} still works after the session was suspended",
            snip(f"{d.get('app')} accepted {d.get('token_type')} {str(tok)[:6]}… from {d.get('src_ip')} at {ev['ts']}; session suspended at {frozen['iso']}"),
            "Revocation did not take effect. Revoke the token at the identity provider and the application directly (not only via the agent platform), then review activity since the suspension.",
            ["T1078.004", "T1528"], key=f"revoked|{tok}", signals=["token issued before the freeze", "accepted after the freeze"],
            identity=user, source_ip=d.get("src_ip"), api_event=f"{d.get('app')} auth"))
    host_ip = eng.hosts.get(ev.get("host"), {}).get("ip")
    ip = d.get("src_ip", "")
    if ip and not in_corp_range(ip) and host_ip and ip != host_ip:
        out.append(make_alert(
            "D10", ev, "high", f"Agent/API token for {user} used from a different, non-corporate address ({ip})",
            snip(f"{d.get('app')} {d.get('token_type')} accepted from {ip}; the developer's machine is {host_ip}"),
            "Tokens that leave the machine they were issued to have been stolen or copied. Revoke the token and review what it accessed.",
            ["T1528", "T1078.004"], key=f"tokloc|{tok}|{ip}", signals=["token used away from its host", "source outside corporate ranges"],
            identity=user, source_ip=ip, api_event=f"{d.get('app')} auth"))
    return out


DETECTORS = [d1_prompt_injection, d2_secret_exposure, d3_supply_chain, d4_unauthorized_shell,
             d5_llm_exfil, d6_config_tampering, d7_git, d9_scm_control, d10_credential_misuse]
