---
title: Telemetry silence or log tampering
rules: D8
owner: Endpoint engineering / SOC on-call
depends: CORP_SOURCE_CIDRS, LOG_COLLECTION_PATHS
version: 1.0
---
## When this fires
- A host stopped reporting while others continue, a log-evasion command ran, or every source went silent.

## First 10 minutes
1. Decide which it is: **tampering** (a stop command ran, one host quiet, critical), **outage** (all sources quiet at once, medium but still a gap), or **a sleeping laptop** (single quiet host, no command).
2. Tampering: EDR host isolation is requested automatically; the SOC lead confirms or releases it.

## Is it real?
- True positive: a log-evasion command followed by silence; a third-party device going dark.
- False positive: laptop asleep or offline, collector maintenance.

## Investigate
- Contact the user and check the device state in MDM. What ran in the last 15 minutes before the silence?
- For an outage: collector and pipeline health, then backfill; list everything that could have happened in the gap.

## Contain and recover
- Restore the log shipper through MDM and backfill the gap (Endpoint engineering). Treat the gap as unobserved.

## Escalate
- Tampering on a third-party device: SOC lead and Vendor management.

## False positives: fix the policy, not the analyst
- Persistent silence from a legitimately offline host class (lab machines): handle through the source inventory, not by lowering the rule.

## Close the case
- Gap documented with its start, end and what it covered.
