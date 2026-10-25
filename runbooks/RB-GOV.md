---
title: Reviewing a register change (checker guide)
rules: register
owner: SOC lead
depends: ESCALATION_ROLES
version: 1.0
---
## When this fires
- A proposal appears in Governance & audit, usually after an analyst closed a case as a false positive.

## First 10 minutes
1. Check the **maker, role and reason**. You must be a different person and more senior (a lead needs another lead).
2. Open the linked case and the runbook of the rule: does the evidence support the claim that this value is normal?

## Is it real?
- Good: a named source (ticket, network team, platform team), a narrow value (one host, one range) and a case reference.
- Bad: a broad value (wide CIDR, a public domain), no evidence, a request made right after an alert fired.

## Investigate
- Ask the entry's owner (named on the entry) to confirm. For a range, check it with the network team before approving.

## Contain and recover
- Approve: the live policy changes at once and is logged. Reject with a note: the maker sees why.

## Escalate
- Anything that would weaken detection for a critical repository or host: lead approval and a note to the CISO.

## False positives: fix the policy, not the analyst
- Nothing is learned automatically. Each approved change should add a benign case to the validation corpus.

## Review-by dates
- Every entry carries a review-by date. Past it the entry **stays in force** (deleting it would switch a detection off) but is flagged here, in the Governance table and in the audit log (`register_review_overdue`).
- Ask the owner to re-confirm. Only an approved *confirm* proposal resets the date; nobody can extend it by editing the file silently.

## Close the case
- Decision recorded; owner informed; entry stays `assumed` until the owner confirms it (a *confirm* proposal).
