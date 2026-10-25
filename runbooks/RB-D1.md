---
title: Prompt injection in content the agent read
rules: D1
owner: AppSec
depends: APPROVED_MCP_SERVERS
version: 1.0
---
## When this fires
- Text aimed at an AI (override, impersonating the system, concealment, hidden HTML comment, data smuggling) appeared in untrusted content: an issue, README, web page, MCP result.

## First 10 minutes
1. Read the case summary: did the agent act afterwards? If **C1** or **C2** is in the case, treat as P1 and follow RB-C1 / RB-C2 instead.
2. A *low* D1 signal is quoted or educational text (security article, unit test). No action unless the agent later acts on it.

## Is it real?
- True positive: the exact instruction appears in the content and the agent's next actions match it, with no human request for them in the prompt.
- False positive: documentation, a test fixture or a security write-up quoting an attack.

## Investigate
- Find the source: issue or PR URL, page, MCP tool. Who can edit it? When was it last changed?
- Read the session timeline from the content event to the end. Which files, commands and destinations followed?
- Search other repos, issues and sessions for the same text (hunt decision).

## Contain and recover
- Remove or block the content source; revoke access of the author if internal or compromised.
- Review credentials the session could reach (RB-D2 / rotate decision).

## Escalate
- If a command executed or data left: P1, SOC lead. If only read: P2 until the agent's actions are reviewed.

## False positives: fix the policy, not the analyst
- Documentation that happens to match is already downgraded to a signal. A repeated legitimate pattern: add a benign case to the validation corpus and tighten the rule via pull request. This rule has no allow-list on purpose.

## Close the case
- Source blocked, hunt result recorded, developer informed.
