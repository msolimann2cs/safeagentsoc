# Phase 1 Troubleshooting Log

| Date | Component | Problem | Cause | Fix | Status |
|---|---|---|---|---|---|
| 2026-05-13 | VMware networking | Wazuh VM had static IP but no internet | VM default route used 10.10.10.1, which was the Windows host-side VMnet10 adapter, not the NAT gateway | Changed VMware NAT gateway to 10.10.10.2 and updated Wazuh/Linux endpoint routes | Fixed |
| 2026-05-13 | Ubuntu Netplan | Wazuh VM had duplicate static and DHCP IPs | Multiple Netplan/cloud-init/NetworkManager configs were active at the same time | Disabled old Netplan configs, disabled cloud-init network regeneration, created one clean static config | Fixed |
| 2026-05-13 | Ubuntu networking renderer | Netplan apply failed with NetworkManager error | Netplan renderer was set to NetworkManager but NetworkManager was not running | Switched Wazuh VM to systemd-networkd renderer | Fixed |
| 2026-05-13 | Linux endpoint networking | Linux endpoint needed corrected gateway | Original gateway assumption used 10.10.10.1 | Reconfigured safesoc-lnx-01 to use gateway 10.10.10.2 | Fixed |
| 2026-05-13 | Evidence process | Screenshots were captured across multiple sprint steps | Evidence timing was not initially explicit | Created evidence naming convention and final evidence index | Fixed |

