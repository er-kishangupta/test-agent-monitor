---
title: Agentic kill chain: injection to action
rules: C1
owner: SOC lead
depends: none
version: 1.0
---
## When this fires
- An indirect prompt injection was followed within 30 minutes by a secret, package, shell, data, agent-config or git alert, or by egress to an unapproved host.

## First 10 minutes
1. Declare P1. Suspend is automatic; confirm host isolation. Open the case: the stages are listed in order.

## Is it real?
- Almost always a true positive: two independent behaviours tied by time and session.

## Investigate
- Timeline from the injection to the last action; the content source; every credential the session could read.

## Contain and recover
- Isolate and rebuild; rotate credentials; block the content source; hunt for the same text elsewhere.

## Escalate
- SOC lead declares the incident; CISO is informed within the target; DPO if data left.

## False positives: fix the policy, not the analyst
- Not applicable: tune the stage rules (D1 to D7) instead.

## Close the case
- Incident declared, scope known, post-incident review booked.
