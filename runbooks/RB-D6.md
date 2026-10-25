---
title: Agent configuration or MCP tampering
rules: D6
owner: AppSec
depends: APPROVED_MCP_SERVERS
version: 1.0
---
## When this fires
- An agent instruction file (rules, CLAUDE.md, AGENTS.md, MCP config, CI workflow) changed in a risky way, or a tool call went to an MCP server that is not approved.

## First 10 minutes
1. Look at the diff in the alert: invisible characters, external URLs, 'do not tell the user', permission to run everything, a new MCP server or a `pull_request_target` checkout.
2. A low signal is a routine edit (style rules, a normal permission). No action.

## Is it real?
- True positive: concealment or exfiltration wording, hidden characters, auto-approve widened, unknown MCP server.
- False positive: a developer's own edit (not agent-generated), an internal health-check URL, an approved MCP server.

## Investigate
- Was the change agent-generated or human? Which commit and branch? Has it merged, and who pulled it?
- What did the unapproved MCP server receive (tool arguments summary)?

## Contain and recover
- Revert the change and require CODEOWNERS review on agent files (repo owner). Remove the unapproved MCP server from developers' configurations.

## Escalate
- Merged to a shared branch: P2 at least, AppSec lead; every developer who pulled it is exposed.

## False positives: fix the policy, not the analyst
- A newly approved MCP server goes into `APPROVED_MCP_SERVERS` through the register after AppSec review.

## Close the case
- Config reverted, review rule in place, hunt result recorded.
