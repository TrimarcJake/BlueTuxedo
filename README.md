# BlueTuxedo
A tiny tool built to find and fix common misconfigurations in Active Directory-Integrated DNS (and a little DHCP as a treat).

## How can BlueTuxedo help you?
[Read the slides from WWHF.](https://github.com/TrimarcJake/BlueTuxedo/blob/main/ADI%20DNS%20-%20No%20demo.pptx)

[Watch the presentation from BSidesCharm.](https://www.hub.trimarcsecurity.com/post/ad-dns-a-match-made-in-heck)

## Quick Start:
``` powershell
git clone https://github.com/TrimarcJake/BlueTuxedo.git
cd BlueTuxedo
Import-Module .\BlueTuxedo.psd1
Invoke-BlueTuxedo
```
Running `Invoke-BlueTuxedo` with no paramters will [`Get`](get-stuff) stuff, `Test` it, then offer code for how to `Repair` identified issues (where possible).

### `Get` Stuff

- ADI Zones
- Conditional Forwarder
- Dangling SPNs [^1]
- DHCP Dynamic Update service account configuration
- DnsAdmins Membership
- Forwarder Configuration
- Global Query Block List (GQBL)
- Non-ADI Zone Auditing
- Query Resolution Policies
- Security Descriptors
- Socket Pool Configuration
- Tombstoned DNS Records
- Wildcard Record
- WPAD Record
- Zone Scopes
- Zone Scope Containers

### `Test` Stuff
| Item | Test Condition |
|---------|---------------|
| ADI Zones | Is Legacy Zone? |
| DHCP Dynamic Update service account | Exists? |
| DnsAdmins Membership | Is non-zero? |
| Forwarder Configuration | Exist? |
| Global Query Block List (GQBL) | Contains `wpad`/`isatap` |
| Non-ADI Zones | Exist? |
| Query Resolution Policies | Exist? |
| Security Descriptor (ACEs) | Standard/Expected? |
| Security Descriptor (Ownership) | Standard/Expected? |
| Socket Pool Configuration | Is maximum? |
| Tombstoned DNS Records | Exist? |
| Wildcard Record | Exists? + Correct type? |
| WPAD Record | Exists? + Correct type? |
| Zone Scopes | Exist? |
| Zone Scope Containers | Exists? + Empty? |

### `Repair` Stuff
| Item | Fix |
|-|-|
| ADI Zones | Convert Legacy (Windows 2000 Compatible) Zones to Modern |
| Dangling SPNs | Delete SPN from Account |
| Socket Pool Configuration | Set Socket Pool Configuration to Maximum |
| Tombstoned DNS Records | Delete Tombstoned DNS Record |
| Wildcard Record | Create Proper Wildcard Record |
| WPAD Record | Create Proper WPAD Record |

[^1]: A "Dangling SPN" is an SPN where the host portion of the SPN does not resolve to an IP address.