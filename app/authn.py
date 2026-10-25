"""Sign-in modes. The monitor does not run its own login screen for staff: in production an identity-aware proxy does that and passes the result in.

  none    no authentication (default for local review; the compose file binds to 127.0.0.1)
  basic   one shared HTTP Basic password (DASHBOARD_USER / DASHBOARD_PASSWORD): keeps strangers out, does not identify anyone
  proxy   SSO through an identity-aware proxy in front of the monitor. Examples that fit: oauth2-proxy with Microsoft Entra ID (Azure AD),
          Entra Application Proxy, or an AWS ALB with OIDC to IAM Identity Center. The proxy authenticates the person (MFA, conditional
          access) and adds headers; the monitor
            1. accepts the headers ONLY from addresses in TRUSTED_PROXY_CIDRS (anyone else can forge a header),
            2. maps directory groups to roles (analyst, senior, lead) using config/platform.json,
            3. denies a signed-in person whose groups map to no role,
            4. stops reading the self-asserted X-Actor / X-Role headers, so maker-checker is enforced on a real identity.
What is NOT built: the OIDC redirect and token validation itself. That is the proxy's job, and it can only be tested against a real tenant.
Headers carry no signature here: a network path that lets anything but the proxy reach the monitor defeats this mode (hence the CIDR check and
the localhost-only compose binding). If the platform offers signed identity tokens (ALB x-amzn-oidc-data), verify them in a production build."""
from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass

from .register import ROLE_RANK

ACTOR_RX = re.compile(r"[^A-Za-z0-9._@ -]")


@dataclass
class Identity:
    actor: str
    role: str
    source: str            # "proxy" | "self-asserted" | "none"
    groups: tuple = ()


def mode() -> str:
    m = os.environ.get("AUTH_MODE", "").strip().lower()
    if m in ("none", "basic", "proxy"):
        return m
    return "basic" if os.environ.get("DASHBOARD_PASSWORD") else "none"


def trusted_cidrs() -> list:
    out = []
    for part in os.environ.get("TRUSTED_PROXY_CIDRS", "").split(","):
        part = part.strip()
        if part:
            try:
                out.append(ipaddress.ip_network(part, strict=False))
            except ValueError:
                pass
    return out


def from_trusted_proxy(client_ip: str) -> bool:
    try:
        ip = ipaddress.ip_address(client_ip)
    except ValueError:
        return False
    return any(ip in n for n in trusted_cidrs())


def role_from_groups(groups: list[str], mapping: dict[str, str]) -> str | None:
    """Highest mapped role among the person's groups. None = no group maps to a role."""
    best = None
    for g in groups:
        r = mapping.get(g.strip())
        if r in ROLE_RANK and (best is None or ROLE_RANK[r] > ROLE_RANK[best]):
            best = r
    return best


def identify_proxy(headers, client_ip: str, sso_cfg: dict) -> tuple[Identity | None, str]:
    """Returns (identity, "") or (None, reason). reason is for the audit log, not for the caller."""
    if not from_trusted_proxy(client_ip):
        return None, "request did not come from a trusted proxy address"
    h = {k.lower(): v for k, v in headers.items()}
    user = (h.get(sso_cfg.get("user_header", "x-forwarded-preferred-username").lower()) or h.get(sso_cfg.get("email_header", "x-forwarded-email").lower()) or "").strip()
    user = ACTOR_RX.sub("", user)[:40]
    if not user:
        return None, "proxy sent no user header"
    groups = [g for g in (h.get(sso_cfg.get("groups_header", "x-forwarded-groups").lower(), "")).replace(";", ",").split(",") if g.strip()][:200]
    role = role_from_groups(groups, sso_cfg.get("group_to_role", {}))
    if role is None:
        return None, f"user {user} is signed in but none of their groups maps to a role"
    return Identity(user, role, "proxy", tuple(groups[:20])), ""
