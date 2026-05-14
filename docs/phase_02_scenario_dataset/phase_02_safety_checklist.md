# Phase 2 Safety Checklist

## Purpose

This checklist defines what is allowed, restricted, and forbidden during SafeAgentSOC Phase 2 scenario and dataset creation.

## Allowed Activities

- Benign command execution
- Discovery commands inside lab VMs
- Safe file creation in test folders
- Harmless scheduled task creation and deletion
- Harmless cron marker creation and deletion
- Failed login simulation inside the lab
- sudo/auth tests inside the Linux endpoint
- Windows Sysmon telemetry generation
- Wazuh dashboard filtering
- Wazuh alert export from lab-generated data

## Restricted Activities

Restricted activities require review before execution:

- Atomic Red Team tests
- Anything that modifies persistence settings
- Anything that creates users
- Anything that changes firewall rules
- Anything that changes security settings
- Anything that creates scheduled tasks or cron jobs
- Anything that generates a large alert volume

Restricted activities must have:
- Scenario ID
- Safety rating
- Cleanup steps
- Expected Wazuh signal
- Screenshot plan

## Forbidden Activities

Do not run:

- Real malware
- Credential dumping
- Password hash dumping
- Ransomware simulation
- Destructive persistence
- File deletion outside test folders
- Real exfiltration
- Third-party scanning
- Production network testing
- External brute force
- Unsafe automated response
- Commands that target systems outside the SafeAgentSOC lab

## Phase 2 Safety Rule

If a test cannot be explained, cleaned up, and mapped to a scenario ID before running it, do not run it.

