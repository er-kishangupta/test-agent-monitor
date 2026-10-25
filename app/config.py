"""Central policy/config. In a real deployment these lists come from CMDB / IdP / package-registry
allowlists; here they are explicit so every detection decision is auditable."""
from __future__ import annotations

import os
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
OUT_DIR = Path(os.environ.get("OUT_DIR", BASE / "out"))
SAMPLE_FILE = Path(os.environ.get("SAMPLE_FILE", BASE / "data" / "sample_events.ndjson"))
GROUND_TRUTH_FILE = BASE / "data" / "ground_truth.json"

# "mock" = write payload to out/webhook_received.ndjson. Set to a real http(s) URL to POST for real.
WEBHOOK_URL = os.environ.get("WEBHOOK_URL", "mock")

# --- Telemetry-silence detector -------------------------------------------------------------
HEARTBEAT_INTERVAL = 300          # log shipper heartbeat (seconds) - documented expectation
GAP_SECONDS = int(os.environ.get("SILENCE_GAP_SECONDS", 3 * HEARTBEAT_INTERVAL))  # 3 missed beats
MIN_HEARTBEATS_TO_BASELINE = 3
TAMPER_LOOKBACK = 900             # a tamper command this close to the last event => tampering, not outage

# --- Kill-chain correlation -----------------------------------------------------------------
CHAIN_WINDOW = 1800               # seconds after an injection alert in which follow-on actions escalate

# --- Egress / LLM policy --------------------------------------------------------------------
# Matched as host or any sub-domain (api.individual.githubcopilot.com, api3.cursor.sh ...), never as a substring.
APPROVED_LLM_HOSTS = {"llm-gw.nb.internal", "githubcopilot.com", "cursor.sh"}
ALLOWED_EGRESS_SUFFIXES = (
    "nb.internal", "github.com", "githubusercontent.com", "npmjs.org", "npmjs.com",
    "pypi.org", "pythonhosted.org", "githubcopilot.com", "cursor.sh", "docker.io", "docker.com",
)
EXFIL_SERVICE_SUFFIXES = (
    "pastebin.com", "paste.ee", "hastebin.com", "ghostbin.com", "transfer.sh", "webhook.site", "requestbin.com",
    "pipedream.net", "ngrok.io", "ngrok-free.app", "trycloudflare.com", "serveo.net", "loca.lt", "file.io",
    "0x0.st", "gofile.io", "anonfiles.com", "mega.nz", "oast.fun", "oast.pro", "interact.sh", "burpcollaborator.net",
    "discord.com", "discordapp.com", "hooks.slack.com", "api.telegram.org",
)
# Processes that are NOT a browser: when one of them talks to a chat/paste/tunnel service it is scripted exfiltration.
SCRIPTING_PROCS = ("bash", "sh", "zsh", "curl", "wget", "python", "python3", "node", "perl", "ruby", "nc", "ncat", "powershell", "pwsh")
RISKY_PORTS_OK = (80, 443, 22, 9418, 53)
BULK_CONTEXT_MIN_BYTES = 1_000_000
BULK_CONTEXT_MULTIPLIER = 8
BULK_CONTEXT_MIN_SAMPLES = 8

# --- SOC AI assistant (optional, off by default; see app/ai_assist.py) ---------------------------
# The only hosts the assistant may call. Change-controlled through the register (maker-checker) like every other policy list.
SOC_AI_ENDPOINTS = {"llm-gw.nb.internal"}

# --- Git policy -----------------------------------------------------------------------------
ORG_GIT_MARKERS = ("github.com/nb-bank/", "github.com:nb-bank/", "git.nb.internal", "gitlab.nb.internal", "dev.azure.com/nb-bank")
# Exact names or glob patterns (fnmatch). 'main-menu-redesign' or 'maintenance/x' are NOT protected.
PROTECTED_BRANCHES = ("main", "master", "develop", "prod", "production", "release/*", "hotfix/*")

# --- Package policy -------------------------------------------------------------------------
INTERNAL_PACKAGES = {"@nb/payments-core", "@nb/ledger-sdk", "nb-risk-engine", "nb-sharia-rules"}
INTERNAL_PREFIXES = ("@nb/", "nb-")
# Registries: an install that points the package manager at anything else is a supply-chain change.
INTERNAL_REGISTRY_HOSTS = ("registry.nb.internal", "pypi.nb.internal", "artifactory.nb.internal")
PUBLIC_REGISTRY_HOSTS = ("registry.npmjs.org", "registry.yarnpkg.com", "pypi.org", "files.pythonhosted.org")
# Legitimate packages whose names are close to a popular one (so edit distance alone must not alert on them)
# and well-known packages that run install scripts.
LOOKALIKE_OK = {"numba", "request", "boto", "pyaml", "pytz", "jest-cli", "just", "reach", "https", "flasks", "djangorestframework"}
KNOWN_INSTALL_SCRIPTS = {"esbuild", "husky", "sharp", "puppeteer", "playwright", "core-js", "protobufjs", "bcrypt", "sqlite3",
                         "node-gyp", "canvas", "fsevents", "cypress", "electron", "grpc", "prisma", "swc", "@swc/core"}
# Pipe-to-shell from these vendor installers is a policy matter (low/medium), not an attack indicator.
TRUSTED_INSTALLERS = ("get.docker.com", "sh.rustup.rs", "install.python-poetry.org", "astral.sh", "bun.sh", "deb.nodesource.com",
                      "rpm.nodesource.com", "awscli.amazonaws.com", "get.helm.sh", "sdk.cloud.google.com",
                      "raw.githubusercontent.com/nvm-sh/nvm/", "raw.githubusercontent.com/Homebrew/install/")
POPULAR_PACKAGES = {
    "requests", "urllib3", "numpy", "pandas", "flask", "django", "fastapi", "pytest", "boto3",
    "cryptography", "pyyaml", "sqlalchemy", "pydantic", "httpx", "lodash", "express", "react",
    "axios", "moment", "webpack", "typescript", "eslint", "jest", "colorama", "setuptools",
}

# --- Agent configuration surfaces (rules files, MCP config, CI) ----------------------------
AGENT_CONFIG_GLOBS = (
    ".cursorrules", ".windsurfrules", ".cursor/rules/*", ".cursor/mcp.json", ".mcp.json",
    ".github/copilot-instructions.md", "CLAUDE.md", "AGENTS.md", ".claude/*",
    ".vscode/settings.json", ".vscode/mcp.json", ".github/workflows/*",
)
# Files that run code automatically when a folder is opened, a package is installed or a container is created. An agent edit here is only
# alerted on a real attack signal (auto-run on folder open, a lifecycle hook that fetches or runs remote code, curl | sh): routine edits are ignored.
BUILD_HOOK_GLOBS = (
    ".vscode/tasks.json", ".vscode/launch.json", ".devcontainer/*", ".husky/*", "package.json", "Makefile", "makefile", "GNUmakefile", "*.mk",
    ".pre-commit-config.yaml", "setup.py",
)


# --- MCP servers ----------------------------------------------------------------------------
APPROVED_MCP_SERVERS = {"github", "web", "jira", "confluence", "postgres-readonly"}

# --- Cloud / identity -----------------------------------------------------------------------
# Source ranges of the bank's NAT / VPN. Documentation ranges are used so nothing here is a real address.
CORP_SOURCE_CIDRS = ("198.51.100.0/24",)
CLOUD_DEFENCE_EVASION = {"StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors", "DeleteFlowLogs", "DisableGuardDuty",
                         "DeleteDetector", "DisableSecurityHub", "DeleteConfigRule"}
CLOUD_PRIV_CHANGE = {"CreateAccessKey", "CreateUser", "CreateLoginProfile", "AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy",
                     "PutRolePolicy", "UpdateAssumeRolePolicy", "AddUserToGroup", "PutBucketPolicy", "PutBucketAcl", "ModifySnapshotAttribute"}
CLOUD_SECRET_READ = {"GetSecretValue", "GetParameter", "GetParameters", "GetParametersByPath", "Decrypt"}
CLOUD_RECON = {"GetCallerIdentity", "ListUsers", "ListRoles", "ListBuckets", "ListAccessKeys", "DescribeInstances", "ListSecrets"}
EXPECTED_SECRET_READERS = {"svc-ci", "ci-deploy-role"}      # identities that legitimately read secrets at deploy time
SECRET_READ_BURST = (5, 300)                                  # >= 5 secret reads by one identity within 5 minutes

# --- Source-control control plane (GitHub / GitLab audit log) -----------------------------
SCM_CONTROL_WEAKENED = {
    "protected_branch.destroy": ("high", "Branch protection removed"),
    "protected_branch.policy_override": ("high", "Branch protection overridden"),
    "repository_branch_protection_evaluation.disable": ("high", "Branch protection evaluation disabled"),
    "secret_scanning.disable": ("high", "Secret scanning disabled"),
    "repository_secret_scanning_push_protection.disable": ("high", "Secret-scanning push protection disabled"),
    "repo.transfer": ("critical", "Repository transferred to another owner"),
    "repo.add_member": ("medium", "Collaborator added to repository"),
    "deploy_key.create": ("high", "Deploy key added"),
    "repo.create_actions_secret": ("medium", "CI secret created or changed"),
    "oauth_authorization.create": ("medium", "OAuth application authorised"),
}

# --- DNS --------------------------------------------------------------------------------------
DNS_TUNNEL_LABEL_LEN = 40            # one label this long, or ...
DNS_TUNNEL_BURST = (20, 60)          # ... 20 queries to one parent domain in 60 s
DNS_TUNNEL_IGNORE = ("cloudfront.net", "amazonaws.com", "azureedge.net", "googleusercontent.com", "akamaiedge.net", "nb.internal")

# --- Assets that raise a case's priority --------------------------------------------------------
CRITICAL_REPOS = ("nb-payments-gateway", "nb-ledger-service", "nb-risk-engine")
CRITICAL_HOSTS = ("ci-runner-",)
THIRD_PARTY_USER_PREFIX = "ext."


# --- Environment context (descriptive facts about the estate; each is overridden from config/environment.json) ---------------
# Not every item is read by a rule: the register marks each entry `policy` (a rule reads it) or `context` (it explains the assumptions the
# design rests on and is what the runbooks and the architecture refer to).
NETWORK_ZONES = ("Corporate / VPN egress (CORP_SOURCE_CIDRS)", "Developer VDI subnet for third-party developers", "CI runner subnet (ci-runner-*)",
                 "Production network: no agent or developer-laptop access", "Internet: only via the egress proxy, DNS via the corporate resolver")
ACCESS_PATHS = ("Employees: SSO + MFA, then VPN/ZTNA to GitHub, registries and the gateways",
                "Third-party developers: VDI only, no local source code, same gateways",
                "Coding agents: reach models only through the LLM gateway and tools only through the MCP gateway",
                "CI runners: pull packages through the registry proxy, cloud access by assumed role")
IDENTITY_TYPES = ("Human employee: SSO user (first.last)", "Third-party developer: user prefixed ext. (THIRD_PARTY_USER_PREFIX)",
                  "Agent identity: short-lived agent_token issued per session and bound to the developer", "Service identity: svc-* accounts and assumed roles (svc-ci)")
AGENT_INVENTORY = ("Cursor", "GitHub Copilot", "nb-codeagent (internal)", "ci-agent (CI/CD)")
LOG_COLLECTION_PATHS = (
    "IDE/agent telemetry: vendor hook or extension, via the log shipper",
    "Shell: auditd / EDR on managed laptops and runners",
    "Git: server-side hooks and webhooks (git_hook)",
    "LLM and MCP gateways: gateway access logs",
    "Egress proxy and DNS resolver logs",
    "Package audit: registry proxy and CI",
    "GitHub audit log: audit-log streaming",
    "Cloud audit log: CloudTrail delivery",
    "Identity provider: sign-in and token events",
    "Log shipper heartbeats every 5 minutes (liveness of every endpoint)")
ESCALATION_ROLES = ("SOC on-call: first responder (MDR L2 hands over here)", "SOC lead: declares an incident", "CISO: executive notification",
                    "DPO / Compliance: customer-data exposure and regulator notification (CBUAE)", "Platform engineering: runners, registries, gateways",
                    "Cloud security: cloud keys and logging", "AppSec: rules files, MCP servers, packages", "Engineering lead: repository owner, history rewrite")


# --- Known-environment register ---------------------------------------------------------------
# Facts about the bank's own estate live in config/environment.json (owner, reason and confirmation status per entry) and override the
# defaults above. This keeps "what is normal here" reviewable and changeable by pull request without touching detection code.
import json as _json

ENV_REGISTER_FILE = Path(os.environ.get("ENV_REGISTER", BASE / "config" / "environment.json"))
ENV_REGISTER: dict = {}


def _load_register() -> None:
    try:
        doc = _json.loads(ENV_REGISTER_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return
    g = globals()
    for key, ent in (doc.get("entries") or {}).items():
        if key not in g or "value" not in ent:
            continue
        default, val = g[key], ent["value"]
        if isinstance(default, (set, frozenset)):
            val = type(default)(val)
        elif isinstance(default, tuple):
            val = tuple(val)
        g[key] = val
        ENV_REGISTER[key] = {k: v for k, v in ent.items() if k != "value"} | {"count": len(val) if hasattr(val, "__len__") and not isinstance(val, str) else 1}


_load_register()
