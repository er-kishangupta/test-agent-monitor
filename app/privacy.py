"""Privacy notice and free-text guard for the case-management area.

Why: analysts type notes, reasons and decisions into cases and into the register. Those fields are stored in the case record and the audit trail and can
be read by everyone with access, so they must not become a store of card data or other sensitive customer data.

Basis (cited as alignment, not as a verified article-by-article mapping; confirm the exact clauses with the bank's compliance team):
  - CBUAE Consumer Protection Regulation and Standards (section 6.1, consumer data and privacy): protect consumer and personal data, limit access to
    authorised staff, disclose only under legal authority or consent, do not keep data longer than needed.
  - PCI DSS v4.0 requirement 3.5.1: a stored card number (PAN) must be unreadable. The safest free-text rule is not to store it at all.

Two layers:
  1. The banner (served by GET /api/privacy-notice so the page and the tests read one text).
  2. A guard that refuses high-confidence card, Emirates ID, IBAN and credential patterns in free text. It is a safety net for mistakes, not a DLP product:
     it uses the same detectors as the alert store (Luhn-valid card with a known prefix, checksum-valid IBAN, Emirates ID, credential formats).
     Switch off with CASE_TEXT_GUARD=off (the banner stays). The refusal never echoes the value, and the audit entry records the type only.
"""
from __future__ import annotations

import os
import re

from .detectors import find_pii, find_secrets

CVV_PIN = re.compile(r"\b(?:cvv2?|cvc2?|pin(?:\s*code)?)\b\s*(?:is|=|:)?\s*\d{3,6}\b", re.I)

NOTICE = {
    "title": "Privacy: do not enter card data or sensitive data here",
    "do_not_enter": [
        "Full card numbers (PAN), CVV/CVC or PIN",
        "Emirates ID, passport numbers, IBAN or account numbers",
        "Passwords, keys, tokens or other credentials",
        "Customer names, phone numbers, addresses or balances",
    ],
    "instead": "Refer to the case ID, alert ID, event time or a masked value (last 4 digits). Evidence stays in the log source, not in the note.",
    "why": "Notes and reasons are kept in the case record and the audit trail, and are visible to everyone with access.",
    "basis": "Aligned with the CBUAE Consumer Protection Regulation (protect and minimise consumer and personal data, restrict access) and PCI DSS 3.5.1 (stored card numbers must be unreadable).",
    "enforcement": "Text that looks like a card number, Emirates ID, IBAN or credential is refused, and the attempt is recorded in the audit trail (type only, never the value).",
}


def mode() -> str:
    return "off" if os.environ.get("CASE_TEXT_GUARD", "block").strip().lower() == "off" else "block"


def notice() -> dict:
    return {**NOTICE, "guard": mode()}


def scan(*texts: str | None) -> list[str]:
    """Labels of sensitive items found (never the values)."""
    labels: list[str] = []
    for t in texts:
        if not t:
            continue
        labels += [lab for lab, _ in find_pii(t)]
        labels += [lab for lab, _ in find_secrets(t, formats_only=True)]
        if CVV_PIN.search(t):
            labels.append("Card CVV/PIN")
    return sorted(set(labels))
