---
title: Source-control safeguard weakened
rules: D9
owner: Engineering lead
depends: ORG_GIT_MARKERS, CRITICAL_REPOS
version: 1.0
---
## When this fires
- GitHub audit log shows branch protection removed, secret scanning or push protection disabled, a repo made public or transferred, a deploy key added, a broad OAuth app authorised or an external collaborator added.

## First 10 minutes
1. Was it the human in the web UI, or an API token while an agent was running? The case says *via API token* and links the agent session if there was one.

## Is it real?
- True positive: not the change the actor intended, a token used while an agent session was active, a public repository.
- False positive: a planned change with a ticket; read-only deploy keys, narrow OAuth scopes and internal collaborators are already treated as normal.

## Investigate
- Everything pushed or downloaded while the control was off; who holds the token.

## Contain and recover
- Restore the safeguard (Engineering lead). Revoke the token at the identity provider (Identity team). Review commits in the window.

## Escalate
- Repository made public: P1, SOC lead and Legal at once.

## False positives: fix the policy, not the analyst
- Planned changes should be announced; add the repo to the maintenance calendar rather than loosening the rule.

## Close the case
- Control restored, token revoked, window reviewed.
