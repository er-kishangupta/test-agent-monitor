---
title: Content-to-command provenance
rules: C2
owner: SOC lead
depends: none
version: 1.0
---
## When this fires
- A command or destination the agent used appears verbatim (or by indicator) in untrusted content it read shortly before.

## First 10 minutes
1. Read the 'Why did this happen?' panel: the excerpt from the content, the seconds between, and who executed. Same handling as RB-C1.

## Is it real?
- True positive: the command text is in the page or issue and the prompt did not ask for it. The page can look entirely ordinary, with no override words.

## Investigate
- The content source and its author; other sessions that read it.

## Contain and recover
- Block the source; isolate; rotate credentials.

## Escalate
- As RB-C1.

## False positives: fix the policy, not the analyst
- Vendor installers copied from documentation are not C2 when they are approved installers (`TRUSTED_INSTALLERS`).

## Close the case
- Source blocked, hunt done.
