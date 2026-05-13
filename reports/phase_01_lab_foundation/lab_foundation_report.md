# Lab Foundation Report

## 1. Objective

The objective of this phase was to build the technical SOC lab foundation, deploy Wazuh as the SIEM/XDR platform, connect Windows and Linux endpoints, and prove that endpoint security events are ingested into Wazuh.

## 2. Lab Architecture

The SafeAgentSOC lab foundation uses a small isolated virtual network containing one Wazuh server and two monitored endpoints. The Wazuh server acts as the central SIEM/XDR platform, while the Windows and Linux endpoints act as telemetry sources.

The selected lab network is `SafeAgentSOC-LabNet` using the `10.10.10.0/24` address range. The Wazuh server is assigned `10.10.10.10`, the Windows endpoint is assigned `10.10.10.21`, and the Linux endpoint is assigned `10.10.10.31`.

The lab is designed to support controlled defensive telemetry collection only. It is not used for testing third-party systems.

### Network Diagram

The network diagram is stored at:

```text
diagrams/network/phase_01_lab_network.png
IP Address Plan
HostIPPurpose
safesoc-wazuh-0110.10.10.10Wazuh server, dashboard, manager
safesoc-win-0110.10.10.21Windows endpoint telemetry
safesoc-lnx-0110.10.10.31Linux endpoint telemetry
3. VM Inventory
VM NameRoleOSIPCPURAMDiskStatus
safesoc-wazuh-01Wazuh serverUbuntu Server 24.04 LTS10.10.10.104 vCPU8 GB100 GBPlanned
safesoc-win-01Windows endpointWindows 10/1110.10.10.212 vCPU4 GB60 GBPlanned
safesoc-lnx-01Linux endpointUbuntu Server 24.04 LTS10.10.10.312 vCPU2 GB30 GBPlanned
4. Wazuh Server Deployment

TBD

Include:

Installation method
System resources
Dashboard URL
Screenshots
Issues and fixes
5. Windows Endpoint Onboarding

TBD

Include:

Wazuh agent installation
Sysmon installation
Windows test events
Screenshots
6. Linux Endpoint Onboarding

TBD

Include:

Wazuh agent installation
SSH/auth logs
sudo logs
Screenshots
7. Log Ingestion Proof
Evidence IDSource VMEvent TypeVisible in Wazuh?Screenshot
TBDsafesoc-win-01Login eventTBDTBD
TBDsafesoc-win-01Sysmon process eventTBDTBD
TBDsafesoc-lnx-01SSH/auth eventTBDTBD
TBDsafesoc-lnx-01sudo eventTBDTBD
8. Problems Faced and Fixes
ProblemCauseFixLesson Learned
TBDTBDTBDTBD
9. Evidence Index
Evidence IDFileDescription
E-P1-0012026-05-12_phase1_network_diagram.pngLab topology and IP plan
E-P1-002phase_01_lab_network.drawioEditable network diagram
10. Success Criteria
Success CriteriaStatus
Wazuh dashboard reachablePending
Windows endpoint active in WazuhPending
Linux endpoint active in WazuhPending
Sysmon installedPending
Windows event visible in WazuhPending
Linux auth/sudo/SSH event visible in WazuhPending
Network diagram completeIn progress
VM inventory completeIn progress
Evidence log completeIn progress
11. Readiness for Next Phase

The next phase will focus on telemetry scenarios and dataset creation. The lab foundation will be ready when Wazuh receives reliable telemetry from both Windows and Linux endpoints.

12. Conclusion

TBD
