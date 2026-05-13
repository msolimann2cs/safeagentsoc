# Troubleshooting Log

| Date | Area | Problem | Symptom | Root Cause | Fix | Status |
|---|---|---|---|---|---|---|
| 2026-05-13 | VMware networking | Wazuh VM had static IP but no internet | ping 8.8.8.8 failed, gateway route pointed to 10.10.10.1 | 10.10.10.1 was the Windows host-side VMnet10 adapter, not the NAT gateway | Changed VMware NAT gateway to 10.10.10.2 and updated Netplan default route | Fixed |
| 2026-05-13 | Ubuntu Netplan | VM had duplicate static and DHCP IPs | 10.10.10.10 and 10.10.10.128 appeared together | Multiple Netplan/cloud-init/NetworkManager configs conflicted | Disabled old Netplan configs, disabled cloud-init networking, used one static config | Fixed |
| 2026-05-13 | Ubuntu networking renderer | Netplan could not apply NetworkManager connection | Error: NetworkManager is not running | Netplan renderer was set to NetworkManager but NetworkManager was inactive | Switched Wazuh VM to systemd-networkd renderer | Fixed |

