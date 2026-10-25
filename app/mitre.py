"""MITRE mappings. ATLAS IDs/names/tactics verified against the official ATLAS dataset (v5.6.0,
github.com/mitre-atlas/atlas-data). ATT&CK IDs are Enterprise matrix. Re-verify at atlas.mitre.org before
quoting externally - ATLAS is revised frequently."""
from __future__ import annotations

# id -> (name, tactic(s), framework)
TECHNIQUES: dict[str, tuple[str, str, str]] = {
    # ATT&CK (Enterprise)
    "T1059": ("Command and Scripting Interpreter", "Execution", "attack"),
    "T1059.004": ("Command and Scripting Interpreter: Unix Shell", "Execution", "attack"),
    "T1552.001": ("Unsecured Credentials: Credentials In Files", "Credential Access", "attack"),
    "T1195.001": ("Supply Chain Compromise: Compromise Software Dependencies and Development Tools", "Initial Access", "attack"),
    "T1567": ("Exfiltration Over Web Service", "Exfiltration", "attack"),
    "T1567.001": ("Exfiltration Over Web Service: Exfiltration to Code Repository", "Exfiltration", "attack"),
    "T1485": ("Data Destruction", "Impact", "attack"),
    "T1562.001": ("Impair Defenses: Disable or Modify Tools", "Defense Evasion", "attack"),
    "T1562.006": ("Impair Defenses: Indicator Blocking", "Defense Evasion", "attack"),
    "T1562.008": ("Impair Defenses: Disable or Modify Cloud Logs", "Defense Evasion", "attack"),
    "T1070.003": ("Indicator Removal: Clear Command History", "Defense Evasion", "attack"),
    "T1098.004": ("Account Manipulation: SSH Authorized Keys", "Persistence", "attack"),
    "T1098.001": ("Account Manipulation: Additional Cloud Credentials", "Persistence", "attack"),
    "T1053.003": ("Scheduled Task/Job: Cron", "Execution / Persistence", "attack"),
    "T1136": ("Create Account", "Persistence", "attack"),
    "T1078.004": ("Valid Accounts: Cloud Accounts", "Initial Access / Defense Evasion", "attack"),
    "T1528": ("Steal Application Access Token", "Credential Access", "attack"),
    "T1530": ("Data from Cloud Storage", "Collection", "attack"),
    "T1580": ("Cloud Infrastructure Discovery", "Discovery", "attack"),
    "T1048": ("Exfiltration Over Alternative Protocol", "Exfiltration", "attack"),
    "T1071.004": ("Application Layer Protocol: DNS", "Command and Control", "attack"),
    "T1572": ("Protocol Tunneling", "Command and Control", "attack"),
    "T1546": ("Event Triggered Execution", "Persistence", "attack"),
    "T1071": ("Application Layer Protocol", "Command and Control", "attack"),
    "T1105": ("Ingress Tool Transfer", "Command and Control", "attack"),
    "T1213.003": ("Data from Information Repositories: Code Repositories", "Collection", "attack"),
    "T1548.003": ("Abuse Elevation Control Mechanism: Sudo and Sudo Caching", "Privilege Escalation", "attack"),
    "T1611": ("Escape to Host", "Privilege Escalation", "attack"),
    "T1195.002": ("Supply Chain Compromise: Compromise Software Supply Chain", "Initial Access", "attack"),
    "T1204.002": ("User Execution: Malicious File", "Execution", "attack"),
    # ATLAS
    "AML.T0051.000": ("LLM Prompt Injection: Direct", "Execution", "atlas"),
    "AML.T0051.001": ("LLM Prompt Injection: Indirect", "Execution", "atlas"),
    "AML.T0053": ("AI Agent Tool Invocation", "Execution / Privilege Escalation", "atlas"),
    "AML.T0055": ("Unsecured Credentials", "Credential Access", "atlas"),
    "AML.T0057": ("LLM Data Leakage", "Exfiltration", "atlas"),
    "AML.T0060": ("Publish Hallucinated Entities", "Resource Development", "atlas"),
    "AML.T0072": ("Reverse Shell", "Command and Control", "atlas"),
    "AML.T0081": ("Modify AI Agent Configuration", "Persistence / Defense Evasion", "atlas"),
    "AML.T0086": ("Exfiltration via AI Agent Tool Invocation", "Exfiltration", "atlas"),
    "AML.T0101": ("Data Destruction via AI Agent Tool Invocation", "Impact", "atlas"),
    "AML.T0010.005": ("AI Supply Chain Compromise: AI Agent Tool", "Initial Access", "atlas"),
}


def technique(tid: str) -> dict:
    name, tactic, fw = TECHNIQUES[tid]
    if fw == "attack":
        url = "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"
    else:
        url = "https://atlas.mitre.org/techniques/" + tid
    return {"id": tid, "name": name, "tactic": tactic, "url": url}


def mitre_block(ids: list[str]) -> dict:
    out = {"attack": [], "atlas": []}
    for tid in ids:
        t = technique(tid)
        out["attack" if TECHNIQUES[tid][2] == "attack" else "atlas"].append(t)
    return out


RULES = {
    "D1": "Prompt Injection",
    "D2": "Secret Exposure",
    "D3": "Supply Chain",
    "D4": "Unauthorized Execution",
    "D5": "LLM Data Exfiltration",
    "D6": "Agent Config Tampering",
    "D7": "Risky Git Operation",
    "D8": "Telemetry Tampering",
    "D9": "Source-Control Control Weakened",
    "D10": "Credential Misuse",
    "C1": "Kill Chain (Correlated)",
    "C2": "Content-to-Command Provenance",
    "C3": "Collection to Exfiltration (Correlated)",
}
