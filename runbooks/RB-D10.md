---
title: Credential misuse in the cloud or identity provider
rules: D10
owner: Cloud security
depends: CORP_SOURCE_CIDRS, EXPECTED_SECRET_READERS, IDENTITY_TYPES
version: 1.0
---
## When this fires
- A key the monitor saw leaked is used; cloud audit logging is stopped; a developer credential creates keys or users; a burst of secret reads; a credential used from an unknown address; a revoked token still accepted; a token used away from its machine.

## First 10 minutes
1. Leaked key used from outside the corporate ranges is P1: disable the key first, ask questions after.
2. **Containment failed** (token accepted after we suspended the session) means revocation did not work: revoke at the identity provider and the application directly.

## Is it real?
- True positive: the key came from a prior D2 alert; source address not in the corporate ranges; developer does not recognise the activity.
- False positive: the developer travelling or off the VPN (check with them), a CI role reading secrets (`EXPECTED_SECRET_READERS`).

## Investigate
- Cloud audit log by key ID since exposure: what was listed, read, created?
- For logging stopped: assume everything after is unobserved.

## Contain and recover
- Disable the key, rotate, review created resources, re-enable logging (Cloud security). Revoke tokens at the identity provider (Identity team).

## Escalate
- P1: SOC lead, CISO; customer-data access: DPO.

## False positives: fix the policy, not the analyst
- Add the real VPN / office egress ranges to `CORP_SOURCE_CIDRS` (network team confirms); add a legitimate deploy role to `EXPECTED_SECRET_READERS`.

## Close the case
- Key dead, activity reviewed, logging verified on.
