Get:
- [x] ADI Zones (Type, Dynamic Update Configuration)
- [x] Conditional Forwarder Auditing
- [x] Dangling SPNs
- [x] DHCP Dynamic Update service account
- [x] DnsAdmins Membership
- [x] DnsUpdateProxy Membership
- [x] Forwarder Configuration
- [x] Global Query Block List (GQBL)
- [x] Name Protection Configuration on DHCP servers
- [x] Non-ADI Zone Auditing
- [x] Query Resolution Policies
- [x] Security Descriptors
- [x] Socket Pool Configuration
- [x] Tombstoned DNS Records
- [x] Wildcard Record
- [x] WPAD Record
- [x] Zone Scopes
- [x] Zone Scope Containers

Test:
- [x] ADI Zones (Legacy vs. non-Legacy)
- [x] ADI Zones (Secure vs. non-Secure)
- [x] Conditional Forwarder Auditing - Unnecessary
- [x] Dangling SPNs - Unnecessary
- [x] DHCP Dynamic Update service account
- [x] DnsAdmins Membership - Unnecessary
- [x] DnsUpdateProxy Membership - Unnecessary
- [ ] Duplicate Zone Names
- [x] Forwarder Configuration
- [x] Global Query Block List (GQBL)
- [ ] Name Protection Configuration on DHCP servers
- [x] Non-ADI Zone Auditing - Unnecessary
- [x] Query Resolution Policies - Unnecessary
- [x] Security Descriptor (ACEs)
- [x] Security Descriptor (Ownership)
- [x] Socket Pool Configuration
- [x] Tombstoned DNS Records - Unnecessary
- [x] Wildcard Record - Check if correct type for forest
- [x] WPAD Record - Check if correct type for forest
- [x] Zone Scopes - Unnecessary
- [x] Zone Scope Containers

Repair
- [x] ADI Zones (Legacy => Non-Legacy)
- [ ] ADI Zones (Non-Secure => Secure)
- [x] Dangling SPNs (Delete)
- [ ] DHCP Dynamic Update service account
- [ ] DnsAdmins Membership
- [ ] DnsUpdateProxy Membership
- [ ] Forwarder Configuration
- [ ] Global Query Block List (GQBL)
- [ ] Non-ADI Zone Auditing
- [ ] Query Resolution Policies
- [x] Socket Pool Configuration
- [x] Tombstoned DNS Records
- [ ] Weird DACLs
- [x] Wildcard Record
- [x] WPAD Record
- [ ] Zone Scope Auditing

Planned Improvements
- [ ] DHCP (Name Protection/Service Account) checks in any forest
