---
title: Collection followed by exfiltration
rules: C3
owner: SOC lead / DPO
depends: ALLOWED_EGRESS_SUFFIXES, ORG_GIT_MARKERS, APPROVED_LLM_HOSTS
version: 1.0
---
## When this fires
- Credentials or sensitive data were gathered in a session, then an outbound channel outside policy appeared (unapproved host, personal fork, DNS tunnel, paste or file service).

## First 10 minutes
1. Treat the data as disclosed. Read what was gathered (stages) and where it went (destination).

## Is it real?
- True positive: the destination is not approved and the developer cannot explain it.
- False positive: reading `.env` then using the approved gateway or the organisation's own remote does not fire.

## Investigate
- Ask the developer whether they sent it knowingly. Check the destination with threat intelligence.

## Contain and recover
- Rotate what was gathered; block the destination; assess notification duties with the DPO.

## Escalate
- P1 when credentials or customer data are involved.

## False positives: fix the policy, not the analyst
- Destination legitimately needed: `ALLOWED_EGRESS_SUFFIXES` via register proposal.

## Close the case
- Destination blocked, credentials rotated, notification decision recorded.
