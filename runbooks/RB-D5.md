---
title: Data leaving through LLM context, egress or DNS
rules: D5
owner: DPO / Network security
depends: APPROVED_LLM_HOSTS, ALLOWED_EGRESS_SUFFIXES, CORP_SOURCE_CIDRS
version: 1.0
---
## When this fires
- Context sent to an unapproved model endpoint, PII or secrets in context (even through the approved gateway), a bulk upload far above the user's baseline, egress to paste or file-sharing services, a shell connecting to a raw IP, or DNS tunnelling.

## First 10 minutes
1. Establish **what data** (fields and record count; evidence is redacted) and **where it went** (endpoint and its terms).
2. Customer data to an unapproved endpoint is a reportable data-protection event: inform the DPO at once, do not wait for the investigation.

## Is it real?
- True positive: customer identifiers with valid structure in context, an unapproved endpoint, a non-corporate destination.
- False positive: a source folder named `customer`, a number that merely looks like a card, a test card in a test, a browser (not the agent) using a chat app.

## Investigate
- Which files were in context and who owns them? Was this a one-off or a pattern over 24 hours?
- For DNS: the parent domain, query count and label length; which process asked?

## Contain and recover
- Block the endpoint at the gateway and egress (Network security decision). Ask the provider to delete the data (DPO / Legal). Restrict the user's agent to the approved gateway.

## Escalate
- Customer data: DPO and Compliance now; they assess CBUAE notification duties. Do not decide notification yourself.

## False positives: fix the policy, not the analyst
- A new approved model endpoint or egress destination: `APPROVED_LLM_HOSTS` / `ALLOWED_EGRESS_SUFFIXES` via register proposal, with the approval reference in the reason.

## Close the case
- Endpoint blocked, provider deletion requested, DPO decision recorded.
