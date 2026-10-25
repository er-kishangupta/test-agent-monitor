---
title: Malicious, confused or hallucinated package
rules: D3
owner: Platform engineering / AppSec
depends: INTERNAL_PACKAGES, INTERNAL_PREFIXES, INTERNAL_REGISTRY_HOSTS, KNOWN_INSTALL_SCRIPTS
version: 1.0
---
## When this fires
- An internal-looking name resolved from a public registry (dependency confusion), a typosquat, a brand-new package with an install script, a package that does not exist, a registry override or an install from a URL.

## First 10 minutes
1. Automatic: the package is added to the blocklist. Check whether the install **script ran**: EDR process start under the install process is the proof (D4 'never-seen binary').
2. Dependency confusion at a high version number (99.x) with an install script is almost always a real attack.

## Is it real?
- True positive: internal scope or name from the public index; a name within two edits of a popular package, young, with an install script.
- False positive: a legitimate older package that shares the `nb-` prefix, or a known package that ships an install script.

## Investigate
- Which build or laptop installed it, and what did the install script do? EDR process tree, egress and DNS from that host in the next 10 minutes.
- Which artefacts were built after the install? Which credentials did the runner hold?

## Contain and recover
- Quarantine and rebuild the runner or laptop (Platform engineering decision). Pin the internal scope to the internal registry, claim the public namespace, add a CI check that fails on internal names resolved publicly.
- Rotate registry, cloud and signing credentials the runner held.

## Escalate
- Install script ran on a runner: P1, SOC lead; pause the release pipeline until artefacts built after the install are verified.

## False positives: fix the policy, not the analyst
- Add the internal package or prefix to `INTERNAL_PACKAGES` / `INTERNAL_PREFIXES` (register) so confusion is detected. Add a legitimate script-running package to `KNOWN_INSTALL_SCRIPTS`. Both go through maker-checker.

## Close the case
- Package blocked at the registry proxy, runner rebuilt, namespace claimed, CI check live.
