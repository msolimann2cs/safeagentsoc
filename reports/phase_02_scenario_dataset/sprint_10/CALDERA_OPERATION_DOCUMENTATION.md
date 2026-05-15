# MITRE Caldera Operation Documentation

## Purpose

MITRE Caldera was used to generate campaign-level adversary-emulation telemetry. This provided a stronger dataset than isolated manual or Atomic tests because it produced multi-step operation evidence.

## Execution Mode

```text
execution_mode = caldera
```

## Campaigns

| Campaign | Platform | Purpose |
|---|---|---|
| C-WIN-01 | Windows | Foothold-to-staging campaign |
| C-LNX-01 | Linux | Access-to-persistence campaign |

## Windows Campaign

`C-WIN-01` represented PowerShell execution, discovery, scheduled task marker activity, and archive/staging.

## Linux Campaign

`C-LNX-01` represented SSH/access probing, sudo/PAM activity, Linux discovery, and persistence-like activity.

## Important Observation

Some Linux Caldera abilities failed because the Sandcat agent did not have root privileges. These failures were retained as realistic failed or blocked attack-like behavior and were useful for policy-aware triage evaluation.

## Metadata Limitation

Some Caldera operation metadata was not recoverable after execution and is marked as `not_recovered`. Correlation was still preserved using campaign ID, run ID, host, timestamp window, Wazuh alerts, and evidence screenshots.

## Evidence

Evidence includes Caldera UI screenshots, operation run screenshots, ability success/failure screenshots, Wazuh alert screenshots, and run log entries.
