---
title: Risky git operation
rules: D7
owner: Engineering lead
depends: PROTECTED_BRANCHES, ORG_GIT_MARKERS
version: 1.0
---
## When this fires
- Force-push (or lease-push) to a protected branch, push or remote added outside the organisation, a credential file staged in a commit, a git hook installed, or a risky bypass.

## First 10 minutes
1. A push to a foreign remote is a copy-out of source code: treat as exfiltration (it also feeds C3). Check what was pushed.

## Is it real?
- True positive: protected branch rewritten, non-org remote, credential file in the commit.
- False positive: force push to a feature branch, a branch that merely starts with `main-`, a certificate file.

## Investigate
- Which commits were rewritten? Compare with the server reflog or backup.
- What was in the foreign repository? Is it public?

## Contain and recover
- Restore the branch (Engineering lead). Delete the foreign copy (Legal / Security). Rotate anything in the pushed commits. Enforce server-side branch protection so force-push is impossible.

## Escalate
- Source or secrets pushed to a public repository: P1, Legal and SOC lead.

## False positives: fix the policy, not the analyst
- A branch that should be protected: add it to `PROTECTED_BRANCHES`. A new bank-owned Git host: add to `ORG_GIT_MARKERS`.

## Close the case
- Branch restored, foreign copy deleted or accepted, protection verified.
