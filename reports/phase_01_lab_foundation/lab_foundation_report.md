# Lab Foundation Report

## 1. Objective

The objective of this phase was to build the technical SOC lab foundation, deploy Wazuh as the SIEM/XDR platform, connect Windows and Linux endpoints, and prove that endpoint security events are ingested into Wazuh.

## 2. Lab Architecture

TBD

Include:
- Network diagram
- IP address plan
- VM roles
- Isolation notes

## 3. VM Inventory

| VM Name | Role | OS | IP | Status |
|---|---|---|---:|---|
| safesoc-wazuh-01 | Wazuh server | Ubuntu Server | 10.10.10.10 | Planned |
| safesoc-win-01 | Windows endpoint | Windows 10/11 | 10.10.10.21 | Planned |
| safesoc-lnx-01 | Linux endpoint | Ubuntu Server | 10.10.10.31 | Planned |

## 4. Wazuh Server Deployment

TBD

Include:
- Installation method
- System resources
- Dashboard URL
- Screenshots
- Issues and fixes

## 5. Windows Endpoint Onboarding

TBD

Include:
- Wazuh agent installation
- Sysmon installation
- Windows test events
- Screenshots

## 6. Linux Endpoint Onboarding

TBD

Include:
- Wazuh agent installation
- SSH/auth logs
- sudo logs
- Screenshots

## 7. Log Ingestion Proof

| Evidence ID | Source VM | Event Type | Visible in Wazuh? | Screenshot |
|---|---|---|---|---|
| TBD | safesoc-win-01 | Login event | TBD | TBD |
| TBD | safesoc-win-01 | Sysmon process event | TBD | TBD |
| TBD | safesoc-lnx-01 | SSH/auth event | TBD | TBD |
| TBD | safesoc-lnx-01 | sudo event | TBD | TBD |

## 8. Problems Faced and Fixes

| Problem | Cause | Fix | Lesson Learned |
|---|---|---|---|
| TBD | TBD | TBD | TBD |

## 9. Evidence Index

TBD

## 10. Success Criteria

| Success Criteria | Status |
|---|---|
| Wazuh dashboard reachable | Pending |
| Windows endpoint active in Wazuh | Pending |
| Linux endpoint active in Wazuh | Pending |
| Sysmon installed | Pending |
| Windows event visible in Wazuh | Pending |
| Linux auth/sudo/SSH event visible in Wazuh | Pending |
| Network diagram complete | Pending |
| VM inventory complete | Pending |
| Evidence log complete | Pending |

## 11. Readiness for Next Phase

The next phase will focus on telemetry scenarios and dataset creation. The lab foundation will be ready when Wazuh receives reliable telemetry from both Windows and Linux endpoints.

## 12. Conclusion

TBD
