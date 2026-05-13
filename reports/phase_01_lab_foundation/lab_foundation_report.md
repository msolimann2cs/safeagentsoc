# Lab Foundation Report

## 1. Objective

The objective of this phase was to build the SafeAgentSOC lab foundation by deploying a Wazuh-based SIEM/XDR environment, onboarding Windows and Linux endpoints, configuring endpoint telemetry, and proving that meaningful endpoint events are ingested into Wazuh.

## 2. Lab Architecture

The lab uses VMware Workstation Pro with VMnet10 as an isolated NAT network. The final subnet is `10.10.10.0/24`.

| Address | Meaning |
|---|---|
| 10.10.10.1 | Windows host-side VMware VMnet10 adapter |
| 10.10.10.2 | VMware NAT gateway |
| 10.10.10.10 | Wazuh server |
| 10.10.10.21 | Windows endpoint |
| 10.10.10.31 | Linux endpoint |

## 3. VM Inventory

| VM Name | Role | IP | Status |
|---|---|---:|---|
| safesoc-wazuh-01 | Wazuh server, indexer, dashboard | 10.10.10.10 | Complete |
| safesoc-win-01 | Windows endpoint, Wazuh agent, Sysmon | 10.10.10.21 | Complete |
| safesoc-lnx-01 | Linux endpoint, Wazuh agent | 10.10.10.31 | Complete |

## 4. Wazuh Server Deployment

The Wazuh server was deployed on `safesoc-wazuh-01`. It hosts the Wazuh manager, indexer, and dashboard. The dashboard was successfully accessed from the host PC at `https://10.10.10.10`.

Evidence:
- Wazuh services running
- Wazuh ports listening
- Dashboard login page reachable
- Dashboard overview accessible after authentication

## 5. Windows Endpoint Onboarding

The Windows endpoint `safesoc-win-01` was configured with static IP `10.10.10.21`, enrolled into Wazuh using the Windows Wazuh agent, and configured with Sysmon for endpoint telemetry.

Verified telemetry:
- Windows agent active in Wazuh
- Sysmon process events
- Windows login/security events

## 6. Linux Endpoint Onboarding

The Linux endpoint `safesoc-lnx-01` was configured with static IP `10.10.10.31`, enrolled into Wazuh using the Linux Wazuh agent, and used to generate SSH/auth and sudo telemetry.

Verified telemetry:
- Linux agent active in Wazuh
- SSH/auth events
- sudo/auth events

## 7. Final Log Ingestion Proof

Sprint 5 validated that Wazuh receives meaningful telemetry from both Windows and Linux endpoints.

| Evidence ID | Source VM | Event Type | Visible in Wazuh? |
|---|---|---|---|
| E-P1-031 | safesoc-win-01 | Sysmon/process event | Yes |
| E-P1-032 | safesoc-win-01 | Login/security event | Yes |
| E-P1-033 | safesoc-lnx-01 | SSH/auth event | Yes |
| E-P1-034 | safesoc-lnx-01 | sudo/auth event | Yes |

## 8. Problems Faced and Fixes

| Problem | Cause | Fix |
|---|---|---|
| Static IP but no internet | Used host VMnet10 adapter as gateway | Corrected NAT gateway to 10.10.10.2 |
| Duplicate static and DHCP IPs | Multiple Netplan/cloud-init configs | Disabled conflicting configs |
| NetworkManager error | Renderer mismatch | Switched to systemd-networkd |
| Evidence scattered across sprints | Screenshots captured during implementation | Created final evidence index |

## 9. Snapshots

| VM | Snapshot | Purpose |
|---|---|---|
| safesoc-wazuh-01 | wazuh-installed-working | Restore Wazuh server after working install |
| safesoc-win-01 | win-agent-sysmon-working | Restore Windows endpoint after Wazuh/Sysmon setup |
| safesoc-lnx-01 | linux-agent-working | Restore Linux endpoint after Wazuh agent setup |

## 10. Success Criteria

| Success Criteria | Status |
|---|---|
| Wazuh dashboard reachable | Complete |
| Windows endpoint active in Wazuh | Complete |
| Linux endpoint active in Wazuh | Complete |
| Sysmon installed | Complete |
| Windows event visible in Wazuh | Complete |
| Linux SSH/auth event visible in Wazuh | Complete |
| Linux sudo event visible in Wazuh | Complete |
| Network diagram complete | Complete |
| VM inventory complete | Complete |
| Evidence log complete | Complete |

## 11. Readiness for Next Phase

The lab is ready for the next phase: telemetry scenario design and dataset creation. The environment can now generate and collect endpoint telemetry from both Windows and Linux systems through Wazuh.

## 12. Conclusion

Phase 1 successfully established the SafeAgentSOC lab foundation. The completed environment provides a working SIEM/XDR base with Windows and Linux telemetry sources, validated agent connectivity, endpoint event ingestion, troubleshooting documentation, and reusable VM snapshots.

