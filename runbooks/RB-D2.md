---
title: Secret or credential exposed
rules: D2
owner: Cloud security / Engineering
depends: EXPECTED_SECRET_READERS
version: 1.0
---
## When this fires
- A credential-shaped value appeared in code the agent wrote, a prompt, LLM context or a shell command; or the agent opened a credential file (low signal).

## First 10 minutes
1. Identify the credential type and system from the case (redacted: you see the pattern, never the value). Is it live? Ask the developer which system it belongs to.
2. Treat a live credential as exposed from the moment it was in a prompt or commit.

## Is it real?
- True positive: valid format with a realistic value in non-test code, or in a prompt or LLM context.
- False positive: placeholder, documentation key (AKIAIOSFODNN7EXAMPLE), hash, config field name, test fixture with a fake value.

## Investigate
- Was it committed or pushed? Check D7 on the same session and the remote.
- Was it sent to a model endpoint (D5)? Which one?
- For AWS keys the monitor remembers the key ID: D10 will alert if it is used. Check the cloud audit log by key ID since exposure.

## Contain and recover
- Rotate the credential (owner decision). Remove from code and, if pushed, from history (Engineering lead: rewrite history). Move to a secrets manager.
- Re-scan the repo for the same value.

## Escalate
- Customer-data or production credential: SOC lead and Cloud security now. Used by a third party: P1 (see RB-D10).

## False positives: fix the policy, not the analyst
- Fake values in tests are downgraded when the pattern is format-only. A new false-positive shape goes into the validation corpus; there is no register entry for secrets because an allow-list for credentials is a risk in itself.

## Close the case
- Credential rotated and confirmed dead, history cleaned if pushed, developer guidance given.
