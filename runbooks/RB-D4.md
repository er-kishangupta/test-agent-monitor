---
title: Unauthorised or risky shell execution
rules: D4
owner: SOC on-call
depends: TRUSTED_INSTALLERS
version: 1.0
---
## When this fires
- A command that is a reverse shell, remote code execution (pipe to shell, decode and run, download then run), destructive, persistence, credential theft or a privileged action without approval; or EDR saw a never-seen binary start from a temp path.

## First 10 minutes
1. Check **who typed it**: the developer, the agent under auto-approve, or a remote party inside a reverse shell. The case says which. EDR 'confirmed' means it ran.
2. Reverse shell or EDR-confirmed execution: P1, isolate the host (SOC lead confirms) and go to RB-C2 if untrusted content supplied the command.

## Is it real?
- True positive: command not asked for in the prompt, auto-approved, network connection to an unknown address, remote operator activity afterwards.
- False positive: vendor installer piped to a shell (already a low signal), routine clean-up inside the project, read-only cloud CLI.

## Investigate
- Process tree and network connections from the host for the 30 minutes after.
- Which files, keys and tokens were readable by that process?
- Did a persistence command (cron, authorized_keys, rc files, new user) run?

## Contain and recover
- Isolate and rebuild the host if executed. Rotate credentials the session could read. Remove auto-approve for the command class.

## Escalate
- Executed with an external connection: P1, SOC lead, incident declaration.

## False positives: fix the policy, not the analyst
- Approved vendor installers: add the host or path to `TRUSTED_INSTALLERS` through a register proposal (checker needed). Do not add a domain just to silence one alert: check it with Platform engineering first.

## Close the case
- Host state known (clean or rebuilt), credentials rotated, command class restricted.
