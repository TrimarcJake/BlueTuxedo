
function Get-BTADIZone {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$Domains
    )

    if ($null -eq $Domains) {
        $Domains = Get-BTTarget
    }

    $Zones = @()
    $ZoneList = @()

    $Root = Get-ADRootDSE
    $RootNC = $Root.rootDomainNamingContext
    $Zones = Get-ADObject -Filter { objectClass -eq 'dNSZone' } -SearchBase "CN=MicrosoftDNS,DC=ForestDnsZones,$RootNC"
    
    foreach ($zone in $Zones) {
        $AddToList = [PSCustomObject]@{
            'Domain'         = (Get-ADForest).RootDomain
            'Zone Name'      = $zone.name
            'Zone Type'      = 'Forest-replicated'
            'Is Reverse?'    = ($zone.name -match '\.in-addr\.arpa$')
            'Dynamic Update' = $zone.DynamicUpdate
        }
        
        $ZoneList += $AddToList
    }

    foreach ($domain in $Domains) {
        $Zones = @()
        $domainDN = (Get-ADDomain -Identity $domain).distinguishedName

        foreach ($context in @('CN=System', 'DC=DomainDnsZones') ) {
            $Zones = Get-ADObject -Filter { objectClass -eq 'dNSZone' } -SearchBase "CN=MicrosoftDNS,$context,$domainDN" -Server $domain
            if ($context -eq 'CN=System') {
                $ZoneType = 'Legacy'
            }
            else {
                $ZoneType = 'Domain-replicated'
            }
            
            foreach ($zone in $Zones) {
                $AddToList = [PSCustomObject]@{
                    'Domain'         = $domain
                    'Zone Name'      = $zone.name
                    'Zone Type'      = $ZoneType
                    'Is Reverse?'    = ($zone.name -match '\.in-addr\.arpa$')
                    'Dynamic Update' = $zone.DynamicUpdate
                }
                
                $ZoneList += $AddToList
            }
        }
    }

    $ZoneList
}
function Get-BTConditionalForwarder {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$Domains
    )

    if ($null -eq $Domains) {
        $Domains = Get-BTTarget
    }

    $ZoneList = @()
    foreach ($domain in $Domains) {
        $DNSServers = Resolve-DnsName -Type NS -Name $domain | Where-Object QueryType -EQ 'A'
        foreach ($dnsServer in $DNSServers) {
            $Zones = Get-DnsServerZone -ComputerName $dnsServer.IP4Address | Where-Object { 
                ($_.IsAutoCreated -eq $false) -and 
                ($_.ZoneType -eq 'Forwarder') -and
                ($_.IsDsIntegrated -eq $true)
            }
            
            foreach ($zone in $Zones) {
                $AddToList = [PSCustomObject]@{
                    'Domain'    = $domain
                    'Zone Name' = $zone.ZoneName
                }
                
                $ZoneList += $AddToList
            }
        }
    }

    $ZoneList
}
function Get-BTDanglingSPN {
    <#
    .SYNOPSIS
    Get dangling SPNs from Active Directory.

    .DESCRIPTION
    Get dangling SPNs from all domains in an Active Directory forest. A dangling SPN is a SPN that references an unresolved hostname.

    .PARAMETER Domains
    The domain (or domains) to check for dangling SPNs. These can be entered as 'domain.com' or "@('domain1.com','domain2.com')".

    .EXAMPLE
    Get-BTDanglingSPN

    Get dangling SPNs in all domains in the current forest.

    .EXAMPLE
    $DanglingSPNs = Get-BTDanglingSPN -Domains 'domain.com' | Group-Object PrincipalIdentityReference

    Get dangling SPNs in domain.com and group them by the principal they are attached to.

    .EXAMPLE
    Get-BTDanglingSPN -Domains @('domain1.com','domain2.com','domain3.com')

    Get danging SPNs in domain1.com, domain2.com, and domain3.com.

    .NOTES
    General notes
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$Domains
    )

    begin {
        # If no domains were specified, get all domains in the current forest.
        if ($null -eq $Domains) {
            $Domains = Get-BTTarget
        }

        # Define a RegEx for valid FQDNs.
        $RegexHostname = '^(?=^.{1,254}$)(^((?!-)[a-zA-Z0-9_-]{1,63}(?<!-)\.)+[a-zA-Z]{2,})$'

        # Initialize the hash tables (does making it ordered help performance?)
        $DanglingSPNList = [hashtable]@{}
        $DNSRecords = [ordered] @{}
    }

    process {
        # Cache all DNS records from all domains to make lookups faster. Will only need Resolve-DnsName for SPNs that refer to public names.
        # Keep this outside the other domain loop so all DNS records will be available for the entire script.
        Write-Host "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Getting DNS records from all domains." -ForegroundColor White -BackgroundColor Black
        foreach ($domain in $Domains) {
            $DomainDNSRecords = Get-DnsServerResourceRecord -ComputerName $domain -ZoneName $domain -ErrorAction SilentlyContinue
            foreach ($record in $DomainDNSRecords) {
                $DNSRecords[$record.HostName] = $record.RecordData
            }
        }

        foreach ($domain in $Domains) {
            # Get all objects with SPNs.
            Write-Host "`n[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] [$domain] Getting AD objects with SPNs." -ForegroundColor White -BackgroundColor Black
            $PrincipalWithSPN = Get-ADObject -Filter { ServicePrincipalName -ne "$null" -and ServicePrincipalName -ne 'kadmin/changepw' } -Properties * -Server $domain
            $PrincipalCount = $PrincipalWithSPN.Count
            Write-Host "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] [$domain] Found $PrincipalCount AD objects with SPNs." -ForegroundColor White -BackgroundColor Black

            # Loop through each security principal that has a SPN.
            $PrincipalProgress = 0
            foreach ($principal in $PrincipalWithSPN) {
                ++$PrincipalProgress
                Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] [$domain] [$PrincipalProgress`/$PrincipalCount] [$($principal.CanonicalName)]"

                # Check each SPN to see if its hostname matches the principal's hostname.
                $CheckSPN = $false
                foreach ($spn in ($principal.serviceprincipalname)) {
                    # Remove the service name, the forward slash, and the port from the SPN to get its hostname.
                    $SPNHostname = ($spn).Split('/')[1].Split(':')[0]
                    $PrincipalHostname = $principal.DnsHostName

                    if ($SPNHostname -eq $PrincipalHostname) {
                        # If FQDNs match, ignore and $CheckSPN stays $false
                        Write-Verbose "$spn`n FQDN Match: `'$PrincipalHostname`' = `'$SPNHostname`'. [CheckSPN = $CheckSPN]"
                        continue
                    }
                    elseif ("${SPNHostname}.${domain}" -eq $PrincipalHostname ) {
                        # Construct FQDN from SPNHostname + Domain and check for an FQDN match with PrincipalHostname.
                        Write-Verbose "`n Short Name Match: `'$PrincipalHostname`' = `'${SPNHostname}.${domain}`'. [CheckSPN = $CheckSPN]"
                        continue
                    }
                    elseif ($SPNHostname -match '^[{]?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}[}]?$') {
                        # Do not inspect domain controller SPNs as long as they are in the DC OU.
                        ## NEED TO ADD EXTRA VALIDATION ##
                        Write-Verbose "`n Domain controller GUID. [CheckSPN = $CheckSPN]"
                        continue
                    }
                    else {
                        # Flag the SPN for inspection if the ServicePrincipal hostname does not match any of the above conditions.
                        $CheckSPN = $true
                        $DnsResourceRecordExist = $false

                        Write-Host "`n[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] [$domain] [$PrincipalProgress`/$PrincipalCount] Inspecting: $spn" -ForegroundColor Cyan
                        # Try to find the hostname in internal DNS zones.
                        if ($DNSRecords[$SPNHostname] -or $DNSRecords["${SPNHostname}.${domain}"]) {
                            # Chcek the cached internal DNS records for the hostname.
                            $DnsResourceRecordExist = $true
                            Write-Host "A DNS record was found for ${SPNHostname}." -ForegroundColor Green -BackgroundColor Black
                            continue
                        }

                        # Check for FQDNs not found in the internal $Domains list.
                        if ( ($SPNHostname -match $RegexHostname) -and -not (($domains | ForEach-Object { $SPNHostname.Contains($_) }) -contains $true) ) {
                            Write-Host "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] [$domain] [$PrincipalProgress`/$PrincipalCount] Checking external hostname: $SPNHostname" -ForegroundColor Cyan
                            # Try to resolve the external hostname.
                            if (Resolve-DnsName -Name $SPNHostname -ErrorAction SilentlyContinue) {
                                $DnsResourceRecordExist = $true
                                Write-Host "$SPNHostname was resolved externally." -ForegroundColor Cyan -BackgroundColor Black
                            }
                            else {
                                # Might need more error handling, but basically the name didn't resolve and it is a dangling SPN.
                                $DnsResourceRecordExist = $false
                            }
                        }

                        # If a DNS record was not found, this is a dangling SPN.
                        if ( -not $DnsResourceRecordExist ) {
                            Write-Host "A DNS record for $SPNHostname was NOT FOUND." -ForegroundColor Red -BackgroundColor Black
                            $DanglingSPN = [PSCustomObject]@{
                                'PrincipalIdentityReference' = ConvertTo-IdentityReference -SID $principal.objectSID
                                'DanglingSPN'                = $spn
                                'PrincipalDistinguishedName' = $principal.distinguishedName
                            }
                            # Avoid adding duplicates to the list (construct a unique key from the CN + SPN).
                            if ( -not $DanglingSPNList[ "$($principal.CanonicalName)`:$spn" ] ) {
                                $DanglingSPNList.Add( "$($principal.CanonicalName)`:$spn", $DanglingSPN )
                            }
                        }
                    } # end if/else hostname checks
                } # end foreach SPN
            } # end foreach principal
            Write-Host "$($PrincipalWithSPN.Count) principles found with SPNs in $domain." -ForegroundColor Cyan -BackgroundColor Black
        } # end foreach domain
    } # end process block

    end {
        # Return the results as an array (should I leave it as a hash table?).
        # Use optional parameters to write this to host, logfile, or clipboard.
        [array]$DanglingSPNList.Values
    } # end end block
} # end function

function Get-BTDnsAdminsMembership {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$Domains
    )

    if ($null -eq $Domains) {
        $Domains = Get-BTTarget
    }

    $ForestDnsAdminsMembership = @()

    foreach ($domain in $Domains) {
        $domainDnsAdminsMembership = Get-ADGroupMember 'DnsAdmins' -Recursive -Server $domain
        # TODO Capture nested members with non-standard PGID
        foreach ($member in $domainDnsAdminsMembership) {
            $principal = [PSCustomObject]@{
                'Group Domain'              = $domain
                'Member Name'               = $member.Name
                'Member Distinguished Name' = $member.distinguishedName
            }
            if ($ForestDnsAdminsMembership.distinguishedName -notcontains $member.distinguishedName) {
                $ForestDnsAdminsMembership += $principal
            }
        }
    }

    $ForestDnsAdminsMembership
}
function Get-BTDnsUpdateProxyMembership {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$Domains
    )

    if ($null -eq $Domains) {
        $Domains = Get-BTTarget
    }

    $ForestDnsUpdateProxyMembership = @()

    foreach ($domain in $Domains) {
        $domainDnsUpdateProxyMembership = Get-ADGroupMember 'DnsUpdateProxy' -Recursive -Server $domain
        # TODO Capture nested members with non-standard PGID
        foreach ($member in $domainDnsUpdateProxyMembership) {
            $principal = [PSCustomObject]@{
                'Group Domain'              = $domain
                'Member Name'               = $member.Name
                'Member Distinguished Name' = $member.distinguishedName
            }
            if ($ForestDnsUpdateProxyMembership.distinguishedName -notcontains $member.distinguishedName) {
                $ForestDnsUpdateProxyMembership += $principal
            }
        }
    }

    $ForestDnsUpdateProxyMembership
}
function Get-BTDynamicUpdateServiceAccount {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$Domains
    )

    if ($null -eq $Domains) {
        $Domains = Get-BTTarget
    }

    $DynamicUpdateServiceAccountList = @()
    $DHCPServers = Get-DhcpServerInDC
    foreach ($dhcpserver in $DHCPServers) {
        $DynamicUpdateServiceAccounts = try {
            Get-DhcpServerDnsCredential -ComputerName $dhcpserver.IPAddress 
        }
        catch {
            [PSCustomObject]@{
                UserName   = 'Not Configured'
                DomainName = 'N/A'
            }
        }
        
        if ($DynamicUpdateServiceAccountList.'Server IP' -notcontains $dhcpserver.IPAddress) {
            foreach ($account in $DynamicUpdateServiceAccounts) {
                $AddToList = [PSCustomObject]@{
                    'Server Name'            = $dhcpserver.dnsName
                    'Server IP'              = $dhcpserver.IPAddress
                    'Service Account Name'   = $account.UserName
                    'Service Account Domain' = $account.DomainName
                }
                
                $DynamicUpdateServiceAccountList += $AddToList
            }
        }
    }

    $DynamicUpdateServiceAccountList
}
function Get-BTForwarderConfiguration {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$Domains
    )

    if ($null -eq $Domains) {
        $Domains = Get-BTTarget
    }

    $ForwarderList = @()
    foreach ($domain in $Domains) {
        $DNSServers = Resolve-DnsName -Type NS -Name $domain | Where-Object QueryType -EQ 'A'
        foreach ($dnsServer in $DNSServers) {
            [array]$Forwarders = Get-DnsServerForwarder -ComputerName $dnsServer.IP4Address
            if ($ForwarderList.'Server IP' -notcontains $dnsServer.IP4Address) {
                foreach ($forwarder in $Forwarders) {
                    $AddToList = [PSCustomObject]@{
                        'Server Name' = $dnsServer.Name
                        'Server IP'   = $dnsServer.IP4Address
                        'Forwarders'  = $forwarder.IPAddress.IPAddressToString
                    }
                }

                $ForwarderList += $AddToList
            }
        }
    }

    $ForwarderList
}
function Get-BTGlobalQueryBlockList {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$Domains
    )

    if ($null -eq $Domains) {
        $Domains = Get-BTTarget
    }

    $GlobalQueryBlockListList = @()
    foreach ($domain in $Domains) {
        $DNSServers = Resolve-DnsName -Type NS -Name $domain | Where-Object QueryType -EQ 'A'
        foreach ($dnsServer in $DNSServers) {
            [array]$GlobalQueryBlockList = Get-DnsServerGlobalQueryBlockList -ComputerName $dnsServer.IP4Address
            if ($GlobalQueryBlockListList.'Server IP' -notcontains $dnsServer.IP4Address) {
                $AddToList = [PSCustomObject]@{
                    'Server Name' = $dnsServer.Name
                    'Server IP'   = $dnsServer.IP4Address
                    'Enabled?'    = $GlobalQueryBlockList.Enable
                    GQBL          = $GlobalQueryBlockList.List
                }
            }

            $GlobalQueryBlockListList += $AddToList
        }
    }

    $GlobalQueryBlockListList
}
function Get-BTNameProtectionConfiguration {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$Domains
    )

    if ($null -eq $Domains) {
        $Domains = Get-BTTarget
    }

    $NameProtectionConfigurationList = @()

    foreach ($dhcpServer in $DHCPServers) {
        $NameProtectionv4Configuration = (Get-DhcpServerv4DnsSetting -ComputerName $dhcpServer.IPAddress).NameProtection
        $NameProtectionv6Configuration = (Get-DhcpServerv6DnsSetting -ComputerName $dhcpServer.IPAddress).NameProtection
        if ($NameProtectionConfigurationList.'Server IP' -notcontains $dhcpServer.IPAddress) {
            $AddToList = [PSCustomObject]@{
                'Server Name'          = $dhcpServer.DnsName
                'Server IP'            = $dhcpServer.IPAddress
                'IPv4 Name Protection' = $NameProtectionv4Configuration
                'IPv6 Name Protection' = $NameProtectionv6Configuration
            }
        }

        $NameProtectionConfigurationList += $AddToList
    }

    $NameProtectionConfigurationList
}

function Get-BTNameServer {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$Domains
    )

    if ($null -eq $Domains) {
        $Domains = Get-BTTarget
    }

    $NameServerList = @()
    foreach ($domain in $Domains) {
        $DNSServers = Resolve-DnsName -Type NS -Name $domain | Where-Object QueryType -EQ 'A'
        foreach ($dnsServer in $DNSServers) {
            if ($NameServerList.'Server IP' -notcontains $dnsServer.IP4Address) {
                $AddToList = [PSCustomObject]@{
                    'Server Name' = $dnsServer.Name
                    'Server IP'   = $dnsServer.IP4Address
                }
            }

            $NameServerList += $AddToList
        }
    }

    $NameServerList
}
function Get-BTNonADIZone {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$Domains
    )

    if ($null -eq $Domains) {
        $Domains = Get-BTTarget
    }

    $ZoneList = @()
    foreach ($domain in $Domains) {
        $DNSServers = Resolve-DnsName -Type NS -Name $domain | Where-Object QueryType -EQ 'A'
        foreach ($dnsServer in $DNSServers) {
            $Zones = Get-DnsServerZone -ComputerName $dnsServer.IP4Address | Where-Object { 
                ($_.IsAutoCreated -eq $false) -and 
                ($_.ZoneType -ne 'Forwarder') -and
                ($_.IsDsIntegrated -eq $false)
            }
            
            foreach ($zone in $Zones) {
                $AddToList = [PSCustomObject]@{
                    'Server Name' = $dnsServer.Name
                    'Server IP'   = $dnsServer.IP4Address
                    'Zone Name'   = $zone.ZoneName
                    'Zone Type'   = $zone.ZoneType
                    'Is Reverse?' = $zone.IsReverseLookupZone
                }
                
                $ZoneList += $AddToList
            }
        }
    }

    $ZoneList
}
function Get-BTQueryResolutionPolicy {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$Domains
    )

    if ($null -eq $Domains) {
        $Domains = Get-BTTarget
    }

    $QueryResolutionPolicyList = @()
    foreach ($domain in $Domains) {
        $DNSServers = Resolve-DnsName -Type NS -Name $domain | Where-Object QueryType -EQ 'A'
        foreach ($dnsServer in $DNSServers) {
            $QueryResolutionPolicies = (Get-DnsServer -ComputerName $dnsServer.IP4Address -ErrorAction Ignore -WarningAction Ignore).ServerPolicies
            if ($QueryResolutionPolicyList.'Server IP' -notcontains $dnsServer.IP4Address) {
                foreach ($policy in $QueryResolutionPolicies) {
                    $AddToList = [PSCustomObject]@{
                        'Server Name'          = $dnsServer.Name
                        'Server IP'            = $dnsServer.IP4Address
                        'QRP Name'             = $policy.Name
                        'QRP Level'            = $policy.Level
                        'QRP Processing Order' = $policy.ProcessingOrder
                        'QRP Enabled?'         = $policy.IsEnabled
                        'QRP Action'           = $policy.Action
                    }

                    $QueryResolutionPolicyList += $AddToList
                }
            }
        }
    }

    $QueryResolutionPolicyList
}
function Get-BTSecurityDescriptor {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$Domains
    )

    if ($null -eq $Domains) {
        $Domains = Get-BTTarget
    }

    $ObjectACLList = @()
    $ForestDN = (Get-ADRootDSE).rootDomainNamingContext
    foreach ($domain in $Domains) {
        $DomainDN = (Get-ADDomain $domain).DistinguishedName
        $DomainNetBIOSName = (Get-ADDomain $domain).NetBIOSName
        $Locations = @()
        if ($ForestDN -eq $DomainDN) {
            $Locations = 'DC=ForestDnsZones', 'DC=DomainDnsZones', 'CN=MicrosoftDNS,CN=System'
        }
        else {
            $Locations = 'DC=DomainDnsZones'
        }
        New-PSDrive -Name $DomainNetBIOSName -PSProvider ActiveDirectory -Server $domain -Root "//RootDSE/" | Out-Null
        $Objects = @()
        foreach ($location in $Locations) {
            $Objects = Get-ADObject -Filter * -SearchBase "$location,$DomainDN" -Server $domain
            foreach ($object in $Objects) {
                $AddToList = Get-Acl "$($DomainNetBIOSName):$($object.DistinguishedName)"
                $AddToList | Add-Member NoteProperty -Name Name -Value $object.Name
                $AddToList | Add-Member NoteProperty -Name DistinguishedName -Value $object.DistinguishedName
                
                $ObjectACLList += $AddToList
            }
        }
    }

    $ObjectACLList
}
function Get-BTSocketPoolSize {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$Domains
    )

    if ($null -eq $Domains) {
        $Domains = Get-BTTarget
    }

    $SocketPoolSizeList = @()
    foreach ($domain in $Domains) {
        $DNSServers = Resolve-DnsName -Type NS -Name $domain | Where-Object QueryType -EQ 'A'
        foreach ($dnsServer in $DNSServers) {
            [int32]$SocketPoolSize = (Get-DnsServerSetting -ComputerName $dnsServer.IP4Address -All -WarningAction Ignore).SocketPoolSize
            if ($SocketPoolSizeList.'Server IP' -notcontains $dnsServer.IP4Address) {
                $AddToList = [PSCustomObject]@{
                    'Server Name'      = $dnsServer.Name
                    'Server IP'        = $dnsServer.IP4Address
                    'Socket Pool Size' = $SocketPoolSize
                }
            }

            $SocketPoolSizeList += $AddToList
        }
    }

    $SocketPoolSizeList
}
function Get-BTTarget {
    param (
        [string]$Forest = (Get-ADForest).Name,
        [string]$InputPath
    )

    if ($InputPath) {
        $Targets = Get-Content $InputPath
    }
    else {
        $Targets = (Get-ADForest $Forest).Domains
    }
    
    $Targets
}
function Get-BTTombstonedNode {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$Domains
    )

    if ($null -eq $Domains) {
        $Domains = Get-BTTarget
    }

    $TombstonedNodeList = @()
    foreach ($domain in $Domains) {
        $domainDN = (Get-ADDomain $domain).DistinguishedName
        $Zones = Get-DnsServerZone -ComputerName $domain
        foreach ($zone in $Zones) {
            $Nodes = Get-DnsServerResourceRecord -ComputerName $domain -ZoneName $zone.ZoneName
            foreach ($node in $Nodes) {
                if ($node.DistinguishedName -like "*$domainDN") {
                    $nodeDetails = Get-ADObject -Identity $node.DistinguishedName -Properties dNSTombstoned -Server $domain
                }
                if ($nodeDetails.dNSTombstoned) {
                    $AddToList = [PSCustomObject]@{
                        'Zone Name'   = $zone.ZoneName
                        'Node Name'   = $node.HostName
                        'Record Type' = $node.RecordType
                        'Node DN'     = $node.DistinguishedName
                    }
                
                    $TombstonedNodeList += $AddToList
                }
            }
        }
    }

    $TombstonedNodeList
}
function Get-BTWildcardRecord {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$Domains
    )

    if ($null -eq $Domains) {
        $Domains = Get-BTTarget
    }

    $WildcardRecordList = @()
    foreach ($domain in $Domains) {
        $RRTypes = @('HInfo', 'Afsdb', 'Atma', 'Isdn', 'Key', 'Mb', 'Md', 'Mf', 'Mg', 'MInfo', 'Mr', 'Mx', 'NsNxt', 'Rp', 'Rt', 'Wks', 'X25', 'A',
            'AAAA', 'CName', 'Ptr', 'Srv', 'Txt', 'Wins', 'WinsR', 'Ns', 'Soa', 'NasP', 'NasPtr', 'DName', 'Gpos', 'Loc', 'DhcId', 'Naptr', 'RRSig',
            'DnsKey', 'DS', 'NSec', 'NSec3', 'NSec3Param', 'Tlsa')
        $WildcardExists = $false
        foreach ($rrtype in $RRTypes) {
            if (Get-DnsServerResourceRecord -ComputerName $domain -ZoneName $domain -RRType $rrtype -Name '*' -ErrorAction Ignore) {
                $WildcardExists = $true
                $ActualRRType = $rrtype
            }
        }

        if ($WildcardExists -eq $true) {
            $AddToList = [PSCustomObject]@{
                'Domain'           = $domain
                'Wildcard Exists?' = $true
                'Wildcard Type'    = $ActualRRType
            } 
        }
        else {
            $AddToList = [PSCustomObject]@{
                'Domain'           = $domain
                'Wildcard Exists?' = $false
                'Wildcard Type'    = 'N/A'
            }
        }
        
        $WildcardRecordList += $AddToList
    }

    $WildcardRecordList
}
function Get-BTWPADRecord {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$Domains
    )

    if ($null -eq $Domains) {
        $Domains = Get-BTTarget
    }

    $WPADRecordList = @()
    foreach ($domain in $Domains) {
        $RRTypes = @('HInfo', 'Afsdb', 'Atma', 'Isdn', 'Key', 'Mb', 'Md', 'Mf', 'Mg', 'MInfo', 'Mr', 'Mx', 'NsNxt', 'Rp', 'Rt', 'Wks', 'X25', 'A',
            'AAAA', 'CName', 'Ptr', 'Srv', 'Txt', 'Wins', 'WinsR', 'Ns', 'Soa', 'NasP', 'NasPtr', 'DName', 'Gpos', 'Loc', 'DhcId', 'Naptr', 'RRSig',
            'DnsKey', 'DS', 'NSec', 'NSec3', 'NSec3Param', 'Tlsa')
        $WPADExists = $false
        foreach ($rrtype in $RRTypes) {
            if (Get-DnsServerResourceRecord -ComputerName $domain -ZoneName $domain -RRType $rrtype -Name 'wpad' -ErrorAction Ignore) {
                $WPADExists = $true
                $ActualRRType = $rrtype
            }
        }

        if ($WPADExists -eq $true) {
            $AddToList = [PSCustomObject]@{
                'Domain'       = $domain
                'WPAD Exists?' = $true
                'WPAD Type'    = $ActualRRType
            } 
        }
        else {
            $AddToList = [PSCustomObject]@{
                'Domain'       = $domain
                'WPAD Exists?' = $false
                'WPAD Type'    = 'N/A'
            }
        }
        
        $WPADRecordList += $AddToList
    }

    $WPADRecordList
}
function Get-BTZoneScope {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$Domains
    )

    if ($null -eq $Domains) {
        $Domains = Get-BTTarget
    }

    $ZoneScopeList = @()
    foreach ($domain in $Domains) {
        $DNSServers = Resolve-DnsName -Type NS -Name $domain | Where-Object QueryType -EQ 'A'
        foreach ($dnsServer in $DNSServers) {
            $ZoneScopes = Get-DnsServerZone -ComputerName $dnsServer.IP4Address | Where-Object { 
                ($_.IsDsIntegrated -eq $true) -and
                ($_.IsReverseLookupZone -eq $false) -and
                ($_.ZoneName -ne 'TrustAnchors')
            } | Get-DnsServerZoneScope -ComputerName $dnsServer.IP4Address -ErrorAction Ignore

            if ($ZoneScopeList.'Server IP' -notcontains $dnsServer.IP4Address) {
                foreach ($scope in $ZoneScopes) {
                    $AddToList = [PSCustomObject]@{
                        'Server Name'     = $dnsServer.Name
                        'Server IP'       = $dnsServer.IP4Address
                        'Zone Scope Name' = $scope.ZoneScope
                    }

                    $ZoneScopeList += $AddToList
                }
            }
        }
    }

    $ZoneScopeList
}
function Get-BTZoneScopeContainer {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$ADIZones
    )

    if ($null -eq $ADIZones) {
        $ADIZones = Get-BTADIZone
    }

    $ZoneScopeContainerList = @()
    foreach ($adizone in $ADIZones) {
        [string]$domainDN = (Get-ADDomain $adizone.Domain).DistinguishedName
        try {
            $zoneScopeDN = Get-ADObject -Identity "CN=ZoneScopeContainer,DC=$($adizone.'Zone Name'),CN=MicrosoftDNS,DC=DomainDnsZones,$domainDN" -Server $adizone.Domain -Properties DistinguishedName -ErrorAction SilentlyContinue
            $AddToList = [PSCustomObject]@{
                Domain                    = $adizone.Domain
                'Zone Name'               = $adizone.'Zone Name'
                'Zone Scope Container DN' = $zoneScopeDN
            }
            $ZoneScopeContainerList += $AddToList
        }
        catch {
        }
    }

    $ZoneScopeContainerList
}
function Repair-BTDanglingSPN {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$DanglingSPNs,
        [switch]$Run = $false
    )

    if ($null -eq $DanglingSPNs) {
        $DanglingSPNs = Get-BTDanglingSPN
        return
    }

    if ($Run) {
        foreach ($danglingspn in $DanglingSPNs) {
            setspn -d $danglingspn.'Dangling SPN' $danglingspn.'Identity Reference'
        }
    }
    else {
        foreach ($danglingspn in $DanglingSPNs) {
            Write-Host "Run the following code block to delete the identified Dangling SPN" -ForegroundColor Green
            Write-Host "SPN: $($danglingspn.'Dangling SPN')" -ForegroundColor Green
            Write-Host "Principal: $($danglingspn.'Identity Reference')" -ForegroundColor Green
            Write-Host "setspn -d $($danglingspn.'Dangling SPN') $($danglingspn.'Identity Reference')"
            Write-Host
        }
    }
}

function Repair-BTTestedADILegacyZone {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$TestedADILegacyZones,
        [switch]$Run = $false
    )

    if ($null -eq $TestedADILegacyZones) {
        $TestedADILegacyZones = Test-BTADILegacyZone
    }

    if ($Run) {
        foreach ($adizone in $TestedADILegacyZones) {
            # $DomainReplicatedZonePartition = "DomainDnsZones.$adizone.Domain"
            $ForestReplicatedZonePartition = "ForestDnsZones.$(Get-ADForest $($adizone.Domain))"
            dnscmd $adizone.Domain /ZoneChangeDirectoryPartition $adizone.'Zone Name' $ForestReplicatedZonePartition
        }
    }
    else {
        foreach ($adizone in $TestedADILegacyZones) {
            Write-Host "Run the following code block to convert the $($adizone.Domain) Zone from a Legacy (Windows 2000 compatible Zone) to a Forest-replicated Zone." -ForegroundColor Green
            Write-Host @"
`$ForestReplicatedZonePartition = 'ForestDnsZones.$(Get-ADForest $($adizone.Domain))'
dnscmd $($adizone.Domain) /ZoneChangeDirectoryPartition $($adizone.'Zone Name') `$ForestReplicatedZonePartition

"@
        }
    }
}
function Repair-BTTestedSocketPoolSize {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$TestedSocketPoolSizes,
        [switch]$Run = $false
    )

    if ($null -eq $TestedSocketPoolSizes) {
        $TestedSocketPoolSizes = Test-BTSocketPoolSize
    }

    if ($Run) {
        foreach ($testedsocketpoolsize in $TestedSocketPoolSizes) {
            $Settings = Get-DnsServerSetting -ComputerName $testedsocketpoolsize.'Server IP' -All
            $Settings.SocketPoolSize = 10000
            Set-DnsServerSetting -ComputerName $testedsocketpoolsize.'Server IP' -InputObject $Settings
        }
    }
    else {
        foreach ($testedsocketpoolsize in $TestedSocketPoolSizes) {
            Write-Host "Run the following code block to set DNS Server $($testedsocketpoolsize.'Server IP') Socket Pool Size to 10,000:" -ForegroundColor Green
            Write-Host @"
`$Settings = Get-DnsServerSetting -ComputerName $($testedsocketpoolsize.'Server IP') -All
`$Settings.SocketPoolSize = 10000
Set-DnsServerSetting -ComputerName $($testedsocketpoolsize.'Server IP') -InputObject `$Settings

"@
        }
    }
}
function Repair-BTTestedWildcardRecord {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$TestedWildcardRecords,
        [switch]$Run = $false
    )

    if ($null -eq $TestedWildcardRecords) {
        $TestedWildcardRecords = Test-BTWildcardRecord
    }

    if ($Run) {
        foreach ($wildcardrecord in $TestedWildcardRecords) {
            $type = "-$($wildcardrecord.'Correct Type')"
            if ($wildcardrecord.'Wildcard Exists?') {
                Remove-DnsServerResourceRecord -ComputerName $wildcardrecord.Domain -ZoneName $wildcardrecord.Domain -RRType $wildcardrecord.'Current Wildcard Type' -Name '*'
            }
            if ($type -eq '-Txt') {
                $AddWildcardScriptBlock = "Add-DnsServerResourceRecord -ComputerName $($wildcardrecord.Domain) -ZoneName $($wildcardrecord.Domain) $type -Name '*' -DescriptiveText '0.0.0.0'"
            }
            elseif ($type -eq '-A') {
                $AddWildcardScriptBlock = "Add-DnsServerResourceRecord -ComputerName $($wildcardrecord.Domain) -ZoneName $($wildcardrecord.Domain) $type -Name '*' -RecordData '0.0.0.0'"
            }
            $ScriptBlock = [scriptblock]::Create($AddWildcardScriptBlock)
            Invoke-Command -ScriptBlock $ScriptBlock
        }
    }
    else {
        foreach ($wildcardrecord in $TestedWildcardRecords) {
            $type = "-$($wildcardrecord.'Correct Type')"
            if ($wildcardrecord.'Wildcard Exists?') {
                Write-Host "Run the following code block to delete the Wildcard Record of incorrect type ($($wildcardrecord.'Current Wildcard Type')) and replace with a Wildcard Record of the correct type ($type) in the $($wildcardrecord.Domain) domain" -ForegroundColor Green
                if ($type -eq '-Txt') {
                    $AddWildcardScriptBlock = "Add-DnsServerResourceRecord -ComputerName $($wildcardrecord.Domain) -ZoneName $($wildcardrecord.Domain) $type -Name '*' -DescriptiveText '0.0.0.0'"
                }
                elseif ($type -eq '-A') {
                    $AddWildcardScriptBlock = "Add-DnsServerResourceRecord -ComputerName $($wildcardrecord.Domain) -ZoneName $($wildcardrecord.Domain) $type -Name '*' -RecordData '0.0.0.0'"
                }
                Write-Host @"
Remove-DnsServerResourceRecord -ComputerName $($wildcardrecord.Domain) -ZoneName $($wildcardrecord.Domain) -RRType $($wildcardrecord.'Current Wildcard Type') -Name '*'
$AddWildcardScriptBlock
              
"@
            }
            else {
                Write-Host "Run the following code block to create a Wildcard Record in the $($wildcardrecord.Domain) domain" -ForegroundColor Green
                if ($type -eq '-Txt') {
                    Write-Host "Add-DnsServerResourceRecord -ComputerName $($wildcardrecord.Domain) -ZoneName $($wildcardrecord.Domain) $type -Name '*' -DescriptiveText '0.0.0.0'"
                }
                elseif ($type -eq '-A') {
                    Write-Host "Add-DnsServerResourceRecord -ComputerName $($wildcardrecord.Domain) -ZoneName $($wildcardrecord.Domain) $type -Name '*' -RecordData '0.0.0.0'"
                }
                Write-Host
            }
        }
    }
}
function Repair-BTTestedWPADRecord {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$TestedWPADRecords,
        [switch]$Run = $false
    )

    if ($null -eq $TestedWPADRecords) {
        $TestedWPADRecords = Test-BTWPADRecord
    }

    if ($Run) {
        foreach ($wpadrecord in $TestedWPADRecords) {
            $type = "-$($wpadrecord.'Correct Type')"
            if ($wpadrecord.'WPAD Exists?') {
                Remove-DnsServerResourceRecord -ComputerName $wpadrecord.Domain -ZoneName $wpadrecord.Domain -RRType $wpadrecord.'Current WPAD Type' -Name 'WPAD'
            }
            if ($type -eq '-Txt') {
                $AddWPADScriptBlock = "Add-DnsServerResourceRecord -ComputerName $($wpadrecord.Domain) -ZoneName $($wpadrecord.Domain) $type -Name 'WPAD' -DescriptiveText '0.0.0.0'"
            }
            elseif ($type -eq '-A') {
                $AddWPADScriptBlock = "Add-DnsServerResourceRecord -ComputerName $($wpadrecord.Domain) -ZoneName $($wpadrecord.Domain) $type -Name 'WPAD' -RecordData '0.0.0.0'"
            }
            $ScriptBlock = [scriptblock]::Create($AddWPADScriptBlock)
            Invoke-Command -ScriptBlock $ScriptBlock
        }
    }
    else {
        foreach ($wpadrecord in $TestedWPADRecords) {
            $type = "-$($wpadrecord.'Correct Type')"
            if ($wpadrecord.'WPAD Exists?') {
                Write-Host "Run the following code block to delete the WPAD Record of incorrect type ($($wpadrecord.'Current WPAD Type')) and replace with a WPAD Record of the correct type ($type) in the $($wpadrecord.Domain) domain" -ForegroundColor Green
                if ($type -eq '-Txt') {
                    $AddWPADScriptBlock = "Add-DnsServerResourceRecord -ComputerName $($wpadrecord.Domain) -ZoneName $($wpadrecord.Domain) $type -Name 'WPAD' -DescriptiveText '0.0.0.0'"
                }
                elseif ($type -eq '-A') {
                    $AddWPADScriptBlock = "Add-DnsServerResourceRecord -ComputerName $($wpadrecord.Domain) -ZoneName $($wpadrecord.Domain) $type -Name 'WPAD' -RecordData '0.0.0.0'"
                }
                Write-Host @"
Remove-DnsServerResourceRecord -ComputerName $($wpadrecord.Domain) -ZoneName $($wpadrecord.Domain) -RRType $($wpadrecord.'Current WPAD Type') -Name 'WPAD'
$AddWPADScriptBlock
              
"@
            }
            else {
                Write-Host "Run the following code block to create a WPAD Record in the $($wpadrecord.Domain) domain" -ForegroundColor Green
                if ($type -eq '-Txt') {
                    Write-Host "Add-DnsServerResourceRecord -ComputerName $($wpadrecord.Domain) -ZoneName $($wpadrecord.Domain) $type -Name 'WPAD' -DescriptiveText '0.0.0.0'"
                }
                elseif ($type -eq '-A') {
                    Write-Host "Add-DnsServerResourceRecord -ComputerName $($wpadrecord.Domain) -ZoneName $($wpadrecord.Domain) $type -Name 'WPAD' -RecordData '0.0.0.0'"
                }
                Write-Host
            }
        }
    }
}
function Repair-BTTombstonedNode {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$TombstonedNodes,
        [switch]$Run = $false
    )

    if ($null -eq $TombstonedNodes) {
        $TombstonedNodes = Get-BTTombstonedNode
    }

    if ($Run) {
        foreach ($tombstonednode in $TombstonedNodes) {
            Remove-ADObject $tombstonednode.'Node DN'
        }
    }
    else {
        foreach ($tombstonednode in $TombstonedNodes) {
            Write-Host "Run the following code block to delete the $($tombstonednode.'Node Name') node from the $($tombstonednode.'Zonee Name') zone." -ForegroundColor Green
            Write-Host @"
Remove-ADObject '$($tombstonednode.'Node DN')'

"@
        }
    }
}
# function Repair-BTThing {
#     [CmdletBinding()]
#     param (
#         [Parameter()]
#         [array]$Things,
#         [switch]$Run = $false
#     )

#     if ($null -eq $Things) {
#         $Things = Get-BTThing
#     }

#     if ($Run) {
#         foreach ($thing in $Things) {
            
#         }
#     } else {
#         foreach ($thing in $Things) {
#             Write-Host "DESCRIPTION OF CODE BLOCK" -ForegroundColor Green
#             Write-Host @"
# CODE BLOCK

# "@
#         }
#     }
# }
function Show-BTCollectedData {
    [CmdletBinding()]
    param (
        [switch]$ShowSecurityDescriptors = $false,
        [switch]$Demo = $false,
        [ValidateSet(
            'All',
            'ADIZones',
            'ConditionalForwarders',
            'DanglingSPNs',
            'DnsAdminsMemberships',
            'DnsUpdateProxyMemberships',
            'DynamicUpdateServiceAccounts',
            'ForwarderConfigurations',
            'GlobalQueryBlockLists',
            'NonADIZones',
            'QueryResolutionPolicys',
            'SecurityDescriptors',
            'SocketPoolSizes',
            'TombstonedNodes',
            'WildcardRecords',
            'WPADRecords',
            'ZoneScopes',
            'ZoneScopeContainers'
        )]
        [string]$Section = 'All',
        $ADIZones,
        $ConditionalForwarders,
        $DanglingSPNs,
        $DnsAdminsMemberships,
        $DnsUpdateProxyMemberships,
        $DynamicUpdateServiceAccounts,
        $ForwarderConfigurations,
        $GlobalQueryBlockLists,
        $NonADIZones,
        $QueryResolutionPolicys,
        $SecurityDescriptors,
        $SocketPoolSizes,
        $TombstonedNodes,
        $WildcardRecords,
        $WPADRecords,
        $ZoneScopes,
        $ZoneScopeContainers
    )

    $Sections = @(
        'ADIZones',
        'ConditionalForwarders',
        'DanglingSPNs',
        'DnsAdminsMemberships',
        'DnsUpdateProxyMemberships',
        'DynamicUpdateServiceAccounts',
        'ForwarderConfigurations',
        'GlobalQueryBlockLists',
        'NonADIZones',
        'QueryResolutionPolicys',
        'SocketPoolSizes',
        'TombstonedNodes',
        'WildcardRecords',
        'WPADRecords',
        'ZoneScopes',
        'ZoneScopeContainers'
    )

    $TitleHashtable = @{
        'Section'                      = 'Friendly Name'
        'ADIZones'                     = 'All ADI Zones'
        'ConditionalForwarders'        = 'All Conditional Forwarders'
        'DanglingSPNs'                 = 'All Dangling SPNs'
        'DnsAdminsMemberships'         = 'DnsAdmins Memberships'
        'DnsUpdateProxyMemberships'    = 'DnsUpdateProxy Memberships'
        'DynamicUpdateServiceAccounts' = 'Dynamic Update Service Account Configuration by DHCP Server'
        'ForwarderConfigurations'      = 'Forwarder Configurations by DNS Server'
        'GlobalQueryBlockLists'        = 'All Global Query Block Lists'
        'NonADIZones'                  = 'All Non-ADI Zones'
        'QueryResolutionPolicys'       = 'All Query Resolution Policies'
        'SecurityDescriptors'          = 'All Security Descriptors'
        'SocketPoolSizes'              = 'Socket Pool Size Configuration by DNS Server'
        'TombstonedNodes'              = 'All Tombstoned Nodes'
        'WildcardRecords'              = 'Wildcard Record Configuration by Domain'
        'WPADRecords'                  = 'WPAD Record Configuration by Domain'
        'ZoneScopes'                   = 'All Zone Scopes'
        'ZoneScopeContainers'          = 'All Zone Scope Containers'
    }

    if ($ShowSecurityDescriptors) {
        $Sections += 'SecurityDescriptors'
    }
    
    if ($Section = 'All') {
        foreach ($entry in $Sections) {
            $Title = $TitleHashtable[$entry]
            if ($null -ne (Get-Variable $entry).Value) {
                if ($Demo) {
                    Clear-Host 
                }
                Write-Host "/--------------- $Title ---------------\" -ForegroundColor Green
                (Get-Variable $entry).Value | Format-List
                Write-Host "\--------------- $Title ---------------/" -ForegroundColor Green
                Read-Host "Press Enter to load the next section"
            }
        }
    }
    else {
        $Title = $TitleHashtable[$Section]
        if ($Demo) {
            Clear-Host 
        }
        Write-Host "/--------------- $Title ---------------\" -ForegroundColor Green
        if ($null -eq (Get-Variable $Section).Value) {
            Write-Host "No data collected for $Title" -ForegroundColor Yellow
        }
        else {
            (Get-Variable $Section).Value | Format-List
        }
        Write-Host "\--------------- $Title ---------------/" -ForegroundColor Green
    }
}
function Show-BTFixes {
    [CmdletBinding()]
    param (
        [switch]$ShowSecurityDescriptors = $false,
        [switch]$Demo,
        [ValidateSet(
            'All',
            'TestedSocketPoolSizes',
            'TombstonedNodes',
            'TestedWildcardRecords',
            'TestedWPADRecords',
            'DanglingSPNs',
            'TestedADILegacyZones'
        )]
        [string]$Section = 'All',
        $ConditionalForwarders,
        $DanglingSPNs,
        $DnsAdminsMemberships,
        $DnsUpdateProxyMemberships,
        $NonADIZones,
        $QueryResolutionPolicys,
        $TombstonedNodes,
        $ZoneScopes,
        $TestedADILegacyZones,
        $TestedADIInsecureUpdateZones,
        $TestedDynamicUpdateServiceAccounts,
        $TestedForwarderConfigurations,
        $TestedGlobalQueryBlockLists,
        $TestedSecurityDescriptorACEs,
        $TestedSecurityDescriptorOwners,
        $TestedSocketPoolSizes,
        $TestedWildcardRecords,
        $TestedWPADRecords,
        $TestedZoneScopeContainers
    )

    $Sections = @(
        'TestedSocketPoolSizes',
        'TombstonedNodes',
        'TestedWildcardRecords',
        'TestedWPADRecords',
        'DanglingSPNs',
        'TestedADILegacyZones'
    )

    $TitleHashtable = @{
        'Section'               = 'Friendly Name'
        'TestedSocketPoolSizes' = 'Set Socket Pool Size To Maximum'
        'TombstonedNodes'       = 'Delete All Tombstoned Nodes'
        'TestedWildcardRecords' = 'Fix Wildcard Record Configuration by Domain'
        'TestedWPADRecords'     = 'Fix WPAD Record Configuration by Domain'
        'DanglingSPNs'          = 'Delete Dangling SPNs'
        'TestedADILegacyZones'  = 'Convert Legacy Zones to ForestDNS Zones'
    }

    if ($ShowSecurityDescriptors) {
        $Sections += 'SecurityDescriptors'
    }
    
    if ($Section = 'All') {
        foreach ($entry in $Sections) {
            $Title = $TitleHashtable[$entry]
            if ($null -ne (Get-Variable $entry).Value) {
                if ($Demo) {
                    Clear-Host 
                }
                Write-Host "/--------------- $Title ---------------\" -ForegroundColor Green
                $ScriptBlock = [scriptblock]::Create($SectionScriptBlock)
                Invoke-Command -ScriptBlock $ScriptBlock
                Write-Host "\--------------- $Title ---------------/" -ForegroundColor Green
                Read-Host "Press Enter to load the next section"
            }
        }
    }
    else {
        $Title = $TitleHashtable[$Section]
        if ($Demo) {
            Clear-Host 
        }
        Write-Host "/--------------- $Title ---------------\" -ForegroundColor Green
        if ($null -eq (Get-Variable $Section).Value) {
            Write-Host "No data collected for $Title" -ForegroundColor Yellow
        }
        else {
            $SectionScriptBlock = "Repair-BT$Section"
            $SectionScriptBlock = $SectionScriptBlock.TrimEnd('s') + " -$Section `$$Section"
            $ScriptBlock = [scriptblock]::Create($SectionScriptBlock)
            Invoke-Command -ScriptBlock $ScriptBlock
        }
        Write-Host "\--------------- $Title ---------------/" -ForegroundColor Green
    }
}
function Show-BTLogo {
    param(
        [string]$Version
    )

    Write-Host '      ::::::::: :::      :::    :::::::::::::::::::::::::::    ::::::    ::::::::::::::::::::::  :::::::: ' -ForegroundColor DarkMagenta -BackgroundColor Black
    Write-Host '     :+:    :+::+:      :+:    :+::+:           :+:    :+:    :+::+:    :+::+:       :+:    :+::+:    :+: ' -ForegroundColor Magenta -BackgroundColor Black
    Write-Host '    +:+    +:++:+      +:+    +:++:+           +:+    +:+    +:+ +:+  +:+ +:+       +:+    +:++:+    +:+  ' -ForegroundColor Magenta -BackgroundColor Black
    Write-Host '   +#++:++#+ +#+      +#+    +:++#++:++#      +#+    +#+    +:+  +#++:+  +#++:++#  +#+    +:++#+    +:+   ' -ForegroundColor DarkBlue -BackgroundColor Black
    Write-Host '  +#+    +#++#+      +#+    +#++#+           +#+    +#+    +#+ +#+  +#+ +#+       +#+    +#++#+    +#+    ' -ForegroundColor DarkBlue -BackgroundColor Black
    Write-Host ' #+#    #+##+#      #+#    #+##+#           #+#    #+#    #+##+#    #+##+#       #+#    #+##+#    #+#     ' -ForegroundColor Blue -BackgroundColor Black
    Write-Host '######### ################## ##########    ###     ######## ###    ######################  ########       ' -ForegroundColor Blue -BackgroundColor Black
    Write-Host "                                                                                           v$Version"   
}

function Show-BTTestedData {
    [CmdletBinding()]
    param (
        [switch]$ShowSecurityDescriptors = $false,
        [switch]$Demo,
        [ValidateSet(
            'All',
            'ConditionalForwarders',
            'DanglingSPNs',
            'DnsAdminsMemberships',
            'DnsUpdateProxyMemberships',
            'NonADIZones',
            'QueryResolutionPolicys',
            'TombstonedNodes',
            'ZoneScopes',
            'TestedADILegacyZones',
            'TestedADIInsecureUpdateZones',
            'TestedDynamicUpdateServiceAccounts',
            'TestedForwarderConfigurations',
            'TestedGlobalQueryBlockLists',
            'TestedSecurityDescriptorACEs',
            'TestedSecurityDescriptorOwners',
            'TestedSocketPoolSizes',
            'TestedWildcardRecords',
            'TestedWPADRecords',
            'TestedZoneScopeContainers'
        )]
        [string]$Section = 'All',
        $ConditionalForwarders,
        $DanglingSPNs,
        $DnsAdminsMemberships,
        $DnsUpdateProxyMemberships,
        $NonADIZones,
        $QueryResolutionPolicys,
        $TombstonedNodes,
        $ZoneScopes,
        $TestedADILegacyZones,
        $TestedADIInsecureUpdateZones,
        $TestedDynamicUpdateServiceAccounts,
        $TestedForwarderConfigurations,
        $TestedGlobalQueryBlockLists,
        $TestedSecurityDescriptorACEs,
        $TestedSecurityDescriptorOwners,
        $TestedSocketPoolSizes,
        $TestedWildcardRecords,
        $TestedWPADRecords,
        $TestedZoneScopeContainers
    )

    $Sections = @(
        'ConditionalForwarders',
        'DanglingSPNs',
        'DnsAdminsMemberships',
        'DnsUpdateProxyMemberships',
        'NonADIZones',
        'QueryResolutionPolicys',
        'TombstonedNodes',
        'ZoneScopes',
        'TestedADILegacyZones',
        'TestedADIInsecureUpdateZones',
        'TestedDynamicUpdateServiceAccounts',
        'TestedForwarderConfigurations',
        'TestedGlobalQueryBlockLists',
        'TestedSocketPoolSizes',
        'TestedWildcardRecords',
        'TestedWPADRecords',
        'TestedZoneScopeContainers'
    )

    $TitleHashtable = @{
        'Section'                            = 'Friendly Name'
        'ConditionalForwarders'              = 'All Conditional Forwarders' 
        'DanglingSPNs'                       = 'All Dangling SPNs' 
        'DnsAdminsMemberships'               = 'DnsAdmins Membership (per-domain)' 
        'DnsUpdateProxyMemberships'          = 'DnsUpdateProxy Membership (per-domain)'
        'NonADIZones'                        = 'All Non-ADI Zones' 
        'QueryResolutionPolicys'             = 'All Query Resolution Policies' 
        'TombstonedNodes'                    = 'All Tombstoned Nodes'
        'ZoneScopes'                         = 'Tested Zone Scopes'
        'TestedADILegacyZones'               = 'Legacy ADI Zones'
        'TestedADIInsecureUpdateZones'       = 'ADI Zones not configured for Secure Updates'
        'TestedDynamicUpdateServiceAccounts' = 'DHCP Servers not configured to use Dynamic Update Service Accounts' 
        'TestedForwarderConfigurations'      = 'All Configured Forwarders' 
        'TestedGlobalQueryBlockLists'        = 'All Global Query Block Lists' 
        'TestedSecurityDescriptorACEs'       = 'Possibly Dangerous ACEs on DNS Objects' 
        'TestedSecurityDescriptorOwners'     = 'Possibly Dangerous Owners of DNS Objects' 
        'TestedSocketPoolSizes'              = 'Socket Pool Sizes Less Than Maximum' 
        'TestedWildcardRecords'              = 'Missing or Invalid Wildcard Records' 
        'TestedWPADRecords'                  = 'Missing or Invalid WPAD Records'
        'TestedZoneScopeContainers'          = 'Empty Zone Scope Containers' 
    }

    $DescriptionHashtable = @{
        'Section'                            = "Description"
        'ConditionalForwarders'              = "Check this list of conditional forwarders.`nAre they still in use?"
        'DanglingSPNs'                       = "Dangling SPNs are Service Principal Names where the 'Host' portion of the SPN does not resolve to an IP address.`nDangling SPNs can be used by an attacker to coerce Kerberos authentication."
        'DnsAdminsMemberships'               = "The DnsAdmins group remains incredibly powereful.`nKeep this group empty if possible.`nIf not possible, ensure the members are protected like Tier 0 assets."
        'DnsUpdateProxyMemberships'          = "Members of DnsUpdateProxy group can update ADI DNS records regardless of existing ownership.`nWhile doing so, they grant Authenticated Users the right to modify the DNS record.`nThis group should be kept empty if possible."
        'NonADIZones'                        = "Non-ADI Zones have their information stored on each DNS server/DC instead of in AD.`nNon-ADI Zones create inconsistency across resolvers."
        'QueryResolutionPolicys'             = "Query Resolution Policies are configured per-server and do not appear in the DNS snap-in.`nAudit these entries to ensure they are apppropriate."
        'TombstonedNodes'                    = "Tombstoned Nodes can be updated by any security principal in the forest.`nRemove these nodes."
        'ZoneScopes'                         = "Zone Scopes can be used to create a fully ADI split-brain DNS.`nEnsure these scopes are appropriate for your environment"
        'TestedADILegacyZones'               = "ADI Zones can be replicated in 3 ways: forest-replicated, domain-replicated, and Windows 2000-compatible mode (aka Legacy).`nLegacy Zones are not protected in the same manner as other zones and inherit ACEs from the domain root.`nThese zones should be converted to one of the other types."
        'TestedADIInsecureUpdateZones'       = "[TODO]"
        'TestedDynamicUpdateServiceAccounts' = "Out-of-the-box, AD-joined computers that receive an IP address from a Windows DHCP server can create and update their own DNS nodes.`nA more secure method of creating these nodes is to configure a Dynamic Update Service Account on each DHCP server.`nWhen configured, Dynamic Update Service Accounts can be used to create DNS records on behalf of computers.`nThis makes auditing DACLs easier.`n`nThe following DNS servers do not use a Dynamic Update Service Account:"
        'TestedForwarderConfigurations'      = "When a local DNS server cannot resolve a request, they send a request to a Forwarder.`nCheck the following list to ensure the Forwarders are approriate for your environment."
        'TestedGlobalQueryBlockLists'        = "Despite the name, Global Query Block Lists are configured per-server.`nEach GQBL contains a list of names that the DNS server will not resolve.`nThis list should contain the 'wpad' and 'isatap' records at a minimum."
        'TestedSecurityDescriptorACEs'       = "The following DNS objects have possibly dangerous Access Control Entries.`nNote: if Dynamic Update Service Accounts are not configured on each DHCP server, this section will be very noisy."
        'TestedSecurityDescriptorOwners'     = "The following DNS objects have possibly dangerous Owners.`nNote: if Dynamic Update Service Accounts are not configured on each DHCP server, this section will be very noisy."
        'TestedSocketPoolSizes'              = "When making requests to Forwarders, DNS servers randomize their source ports to minimize AITM attacks.`nThe number of ports used is configured on each DNS Server via the Socket Pool Size value.`nBy default, this is 2500 ports, but the maximum is 10,000.`nConfigure each DNS server to use the maximum value."
        'TestedWildcardRecords'              = "If a Wildcard Record does not exist in a domain, an attacker can create one which points at a device they control.`nAny DNS requests that do not match an existing DNS entry will resolve to the IP of the attacker-controlled machine."
        'TestedWPADRecords'                  = "WPAD is used to allow clients to auto-discover web proxy servers in their environment.`nIf a WPAD Record does not exist in a domain, an attacker can create one which points at a device they control.`nThis configuration could redirect all web traffic to the attacker-controller machine"
        'TestedZoneScopeContainers'          = "Zone Scope Containers hold Zone Scopes.`nIf a Zone Scope Container is empty, this may be an indicator of fuckery (IOF)."
    }

    if ($ShowSecurityDescriptors) {
        $Sections += 'TestedSecurityDescriptorACEs', 'TestedSecurityDescriptorOwners'
    }
    
    if ($Section = 'All') {
        foreach ($entry in $Sections) {
            $Title = $TitleHashtable[$entry]
            $Description = $DescriptionHashtable[$entry]
            if ($null -ne (Get-Variable $entry).Value) {
                if ($Demo) {
                    Clear-Host 
                }
                Write-Host "/--------------- $Title ---------------\" -ForegroundColor Red
                Write-Host $Description
                (Get-Variable $entry).Value | Format-List
                Write-Host "\--------------- $Title ---------------/" -ForegroundColor Red
                Read-Host "Press Enter to load the next section"
            }
        }
    }
    else {
        $Title = $TitleHashtable[$Section]
        $Description = $DescriptionHashtable[$Section]
        if ($Demo) {
            Clear-Host 
        }
        Write-Host "/--------------- $Title ---------------\" -ForegroundColor Red
        Write-Host $Description
        if ($null -eq (Get-Variable $Section).Value) {
            Write-Host "No data collected for $Title" -ForegroundColor Yellow
        }
        else {
            (Get-Variable $Section).Value
        }
        Write-Host "\--------------- $Title ---------------/" -ForegroundColor Red
    }
}
function Test-BTADIInsecureUpdateZone {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$ADIZones
    )

    if ($null -eq $ADIZones) {
        $ADIZones = Get-BTADIZone
    }

    $FailedADIZoneList = @()

    foreach ($adizone in $ADIZones) {
        if ( ($adizone.'Zone Type' -ne 'Stub') -and ($adizone.'Dynamic Update' -ne 'Secure') ) {
            $FailedADIZoneList += $adizone
        }
    }

    $FailedADIZoneList
}
function Test-BTADILegacyZone {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$ADIZones
    )

    if ($null -eq $ADIZones) {
        $ADIZones = Get-BTADIZone
    }

    $FailedADIZoneList = @()

    foreach ($adizone in $ADIZones) {
        if ($adizone.'Zone Type' -eq 'Legacy') {
            [string]$domainDN = (Get-ADDomain $adizone.Domain).DistinguishedName
            try {
                $zoneDN = Get-ADObject -Identity "DC=$($adizone.'Zone Name'),CN=MicrosoftDNS,CN=System,$domainDN" -Server $adizone.Domain -Properties DistinguishedName -ErrorAction SilentlyContinue 
                $AddToList = [PSCustomObject]@{
                    'Domain'      = $adizone.Domain
                    'Zone Name'   = $adizone.'Zone Name'
                    'Zone Type'   = $adizone.'Zone Type'
                    'Is Reverse?' = $adizone.'Is Reverse?'
                    'Zone DN'     = $zoneDN
                }
            }
            catch {
            }
            
            $FailedADIZoneList += $AddToList
        }
    }

    $FailedADIZoneList
}
function Test-BTDynamicUpdateServiceAccount {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$DynamicUpdateServiceAccounts
    )

    if ($null -eq $DynamicUpdateServiceAccounts) {
        $DynamicUpdateServiceAccounts = Get-BTDynamicUpdateServiceAccount
    }

    $FailedDynamicUpdateServiceAccount = @()
    foreach ($dynamicupdateserviceaccount in $DynamicUpdateServiceAccounts) {
        if ( ($dynamicupdateserviceaccount.'Service Account Name' -eq 'Not Configured') -and 
            ($dynamicupdateserviceaccount.'Service Account Domain' -eq 'N/A') ) {
            $FailedDynamicUpdateServiceAccount += $dynamicupdateserviceaccount
        }
    }

    $FailedDynamicUpdateServiceAccount
}
function Test-BTForwarderConfiguration {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$ForwarderConfigurations
    )

    if ($null -eq $ForwarderConfigurations) {
        $ForwarderConfigurations = Get-BTForwarderConfiguration
    }

    $AuditedForwarderConfiguration = @()
    $ForwarderHashtable = @{
        'AdGuard Primary'                               = '94.140.14.14'
        'AdGuard Secondary'                             = '94.140.15.15'  
        'Alternate Primary'                             = '76.76.19.19'   
        'Alternate Secondary'                           = '76.223.122.150'
        'CleanBrowsing Primary'                         = '185.228.168.9'  
        'CleanBrowsing Secondary'                       = '185.228.169.9' 
        'Cloudflare Primary'                            = '1.1.1.1'       
        'Cloudflare Secondary'                          = '1.0.0.1'
        'Cloudflare Primary (Malware Filtered)'         = '1.1.1.2'       
        'Cloudflare Secondary (Malware Filtered)'       = '1.0.0.2'
        'Cloudflare Primary (Malware/Adult Filtered)'   = '1.1.1.3'       
        'Cloudflare Secondary (Malware/Adult Filtered)' = '1.0.0.3'
        'Comodo Secure Primary'                         = '8.26.56.26'     
        'Comodo Secure Secondary'                       = '8.20.247.20'
        'Control D Primary'                             = '76.76.2.0'   
        'Control D Secondary'                           = '76.76.10.0'
        'Google Primary'                                = '8.8.8.8'       
        'Google Secondary'                              = '8.8.4.4'
        'OpenDNS Home Primary'                          = '208.67.222.222'
        'OpenDNS Home Secondary'                        = '208.67.220.220'
        'Quad9 Primary'                                 = '9.9.9.9'      
        'Quad9 Secondary'                               = '149.112.112.112'
    }
    foreach ($forwarderconfiguration in $ForwarderConfigurations) {
        foreach ($forwarder in $forwarderconfiguration.Forwarders) {
            $resolveForwarder = Resolve-DnsName -Name $forwarder -ErrorAction Ignore
            $forwarderName = 'N/A'
            $wellKnown = $false
            $wellKnownName = 'N/A'
            if ($resolveForwarder) {
                $forwarderName = $resolveForwarder.NameHost
                foreach ($h in $ForwarderHashtable.GetEnumerator() ) {
                    if ($h.Value -eq $forwarder) {
                        $wellKnown = $true
                        $wellKnownName = $h.Name
                    }
                }
            }
            $AddToList = [PSCustomObject]@{
                'Server Name'    = $forwarderconfiguration.'Server Name'
                'Server IP'      = $forwarderconfiguration.'Server IP'
                'Forwarder IP'   = $forwarder
                'Forwarder Name' = $forwarderName
                'Well-Known?'    = $wellKnown
                'Service'        = $wellKnownName
            }

            $AuditedForwarderConfiguration += $AddToList
        }
    }

    $AuditedForwarderConfiguration
}
function Test-BTGlobalQueryBlockList {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$GlobalQueryBlockLists
    )

    if ($null -eq $GlobalQueryBlockLists) {
        $GlobalQueryBlockLists = Get-BTGlobalQueryBlockList
    }

    $FailedGlobalQueryBlockList = @()
    foreach ($globalqueryblocklist in $GlobalQueryBlockLists) {
        $wpadExists = $true
        $isatapExists = $true
        if ($globalqueryblocklist.GQBL -notcontains 'wpad') {
            $wpadExists = $false
        }
        if ($globalqueryblocklist.GQBL -notcontains 'isatap') {
            $isatapExists = $false
        }

        if ( ($globalqueryblocklist.'Enabled?' -eq $false) -or ($wpadExists = $false) -or ($isatapExists -eq $false) ) {
            $AddToList = [PSCustomObject]@{
                'Server Name'   = $globalqueryblocklist.'Server Name'
                'Server IP'     = $globalqueryblocklist.'Server IP'
                'Enabled?'      = $globalqueryblocklist.'Enabled?'
                'WPAD Exists'   = $wpadExists
                'ISATAP Exists' = $isatapExists
            }
        }

        $FailedGlobalQueryBlockList += $AddToList
    }

    $FailedGlobalQueryBlockList
}
function Test-BTSecurityDescriptorACE {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$SecurityDescriptors,
        [Parameter()]
        [array]$DynamicUpdateServiceAccounts,
        [Parameter()]
        [array]$Domains
    )

    if ($null -eq $SecurityDescriptors) {
        $SecurityDescriptors = Get-BTSecurityDescriptor
    }

    if ($null -eq $DynamicUpdateServiceAccounts) {
        $DynamicUpdateServiceAccounts = Get-BTDynamicUpdateServiceAccount
    }

    if ($null -eq $Domains) {
        $Domains = Get-BTTarget
    }

    $FailedSecurityDescriptorACE = @()
    $SafeSIDs = 'S-1-5-9|S-1-5-10|S-1-5-18|S-1-5-32-544'
    $RootDomain = (Get-ADForest $Domains[0]).RootDomain
    $EnterpriseAdminsSID = "$((Get-ADDomain $rootDomain).domainSID.Value)-519"
    $SafeSIDs += "|$EnterpriseAdminsSID"
    # Need to loop through domains
    $KeyAdminsSID = "$((Get-ADDomain $rootDomain).domainSID.Value)-526"
    $EnterpriseKeyAdminsSID = "$((Get-ADDomain $rootDomain).domainSID.Value)-527"
    foreach ($domain in $Domains) {
        $DomainSID = (Get-ADDomain $domain).DomainSID.Value
        $SafeGroupRIDs = @('-512')
        foreach ($rid in $SafeGroupRIDs ) {
            $SafeGroupSID = $DomainSID + $rid
            $SafeSIDs += "|$SafeGroupSID"
        }
    }
    # $DomainAdminsSIDs = foreach ($domain in $Domains) {
    #     "$((Get-ADDomain $domain).domainSID.Value)-512"
    # }
    # foreach ($sid in $DomainAdminsSIDs) {
    #     $SafeSIDs += "|$sid"
    # }
    foreach ($domain in $Domains) {
        $DomainSID = (Get-ADDomain $domain).DomainSID.Value
        $SafeGroupRIDs = @('-516')
        foreach ($rid in $SafeGroupRIDs ) {
            $DomainControllersSID = $DomainSID + $rid
            $SafeSIDs += "|$DomainControllersSID"
            $members = @()
            $members += (Get-ADGroupMember $DomainControllersSID -Server $domain -Recursive).SID.Value
            foreach ($member in $members) {
                $SafeSIDs += "|$member"
            }
        }
    }
    $DangerousRights = 'GenericAll|WriteDacl|WriteOwner|WriteProperty'

    foreach ($dynamicupdateserviceaccount in $DynamicUpdateServiceAccounts) {
        if ( ($dynamicupdateserviceaccount.'Service Account Name' -ne 'Not Configured') -and
            ($dynamicupdateserviceaccount.'Service Account Domain' -ne 'N/A') ) {
            $identityreference = "$($dynamicupdateserviceaccount.'Service Account Domain')\$($dynamicupdateserviceaccount.'Service Account Name')"
            $dynamicupdateserviceaccountSID = ConvertFrom-IdentityReference -Object $identityreference
            $SafeSIDs += "|$dynamicupdateserviceAccountSID"
        }
    }

    foreach ($securitydescriptor in $SecurityDescriptors) {
        foreach ($ace in $securitydescriptor.Access) {
            $aceName = $securitydescriptor.Owner.split('\')[1]
            if ($aceName.EndsWith('$')) {
                $aceName = $aceName.TrimEnd('$')
            }
            $aceSID = ConvertFrom-IdentityReference -Object $ace.IdentityReference 
            if ( ($aceSID -notmatch $SafeSIDs) -and ($ace.ActiveDirectoryRights -match $DangerousRights) -and 
                ($securitydescriptor.DistinguishedName -notmatch $aceName) -and
                ( ($aceSID -notmatch "$EnterpriseKeyAdminsSID|$KeyAdminsSID") -and ($ace.'Object Type' -ne '5b47d60f-6090-40b2-9f37-2a4de88f3063') ) ) {
                $AddToList = [PSCustomObject]@{
                    Name                      = $securitydescriptor.Name
                    'Identity Reference'      = $ace.IdentityReference
                    'Active Directory Rights' = $ace.ActiveDirectoryRights
                    'Object Type'             = $ace.ObjectType
                    'Inherited Object Type'   = $ace.InheritedObjectType
                }
                $FailedSecurityDescriptorACE += $AddToList
            }
        }
    }

    $FailedSecurityDescriptorACE
}
function Test-BTSecurityDescriptorOwner {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$SecurityDescriptors,
        [Parameter()]
        [array]$DynamicUpdateServiceAccounts,
        [Parameter()]
        [array]$Domains
    )

    if ($null -eq $SecurityDescriptors) {
        $SecurityDescriptors = Get-BTSecurityDescriptor
    }

    if ($null -eq $DynamicUpdateServiceAccounts) {
        $DynamicUpdateServiceAccounts = Get-BTDynamicUpdateServiceAccount
    }

    if ($null -eq $Domains) {
        $Domains = Get-BTTarget
    }

    $FailedSecurityDescriptorOwner = @()
    $SafeSIDs = 'S-1-5-18'
    $RootDomain = (Get-ADForest $Domains[0]).RootDomain
    $EnterpriseAdminsSID = "$((Get-ADDomain $rootDomain).domainSID.Value)-519"
    $SafeSIDs += "|$EnterpriseAdminsSID"
    $DomainAdminsSIDs = foreach ($domain in $Domains) {
        "$((Get-ADDomain $domain).domainSID.Value)-512"
    }
    foreach ($sid in $DomainAdminsSIDs) {
        $SafeSIDs += "|$sid"
    }

    foreach ($dynamicupdateserviceaccount in $DynamicUpdateServiceAccounts) {
        if ( ($dynamicupdateserviceaccount.'Service Account Name' -ne 'Not Configured') -and
            ($dynamicupdateserviceaccount.'Service Account Domain' -ne 'N/A') ) {
            $identityreference = "$($dynamicupdateserviceaccount.'Service Account Domain')\$($dynamicupdateserviceaccount.'Service Account Name')"
            $dynamicupdateserviceaccountSID = ConvertFrom-IdentityReference -Object $identityreference
            $SafeSIDs += "|$dynamicupdateserviceAccountSID"
        }
    }

    foreach ($securitydescriptor in $SecurityDescriptors) {
        $owner = $securitydescriptor.Owner
        $ownerName = $securitydescriptor.Owner.split('\')[1]
        if ($ownerName.EndsWith('$')) {
            $ownerName = $ownerName.TrimEnd('$')
        }
        $ownerSID = ConvertFrom-IdentityReference -Object $owner
        if ( ($ownerSID -notmatch $SafeSIDs) -and ($securitydescriptor.DistinguishedName -notmatch $ownerName) ) {
            $FailedSecurityDescriptorOwner += $securitydescriptor | Select-Object Name, Owner, DistinguishedName
        }
    }

    $FailedSecurityDescriptorOwner
}
function Test-BTSocketPoolSize {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$SocketPoolSizes
    )

    if ($null -eq $SocketPoolSizes) {
        $SocketPoolSizes = Get-BTSocketPoolSize
    }

    $FailedSocketPoolSize = @()
    foreach ($socketpoolsize in $SocketPoolSizes) {
        if ($socketpoolsize.'Socket Pool Size' -lt 10000) {
            $FailedSocketPoolSize += $socketpoolsize
        }
    }

    $FailedSocketPoolSize
}
function Test-BTWildcardRecord {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$WildcardRecords
    )

    if ($null -eq $WildcardRecords) {
        $WildcardRecords = Get-BTWildcardRecord
    }

    if ($WildcardRecords -eq 1) {
        $correctType = 'A'
    }
    else {
        $correctType = 'Txt'
    }
    $FailedWildcardRecord = @()
    foreach ($wildcardrecord in $WildcardRecords) {
        if ($wildcardrecord.'Wildcard Type' -ne $correctType) {
            $AddToList = [PSCustomObject]@{
                'Domain'                = $wildcardrecord.'Domain'
                'Wildcard Exists?'      = $wildcardrecord.'Wildcard Exists?'
                'Current Wildcard Type' = $wildcardrecord.'Wildcard Type'
                'Correct Type'          = $correctType
            }
        }

        $FailedWildcardRecord += $AddToList
    }

    $FailedWildcardRecord
}
function Test-BTWPADRecord {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$WPADRecords
    )

    if ($null -eq $WPADRecords) {
        $WPADRecords = Get-BTWPADRecord
    }

    if ($WPADRecords -eq 1) {
        $correctType = 'A'
    }
    else {
        $correctType = 'Txt'
    }
    $FailedWPADRecord = @()
    foreach ($wpadrecord in $WPADRecords) {
        if ($wpadrecord.'WPAD Type' -ne $correctType) {
            $AddToList = [PSCustomObject]@{
                'Domain'            = $wpadrecord.'Domain'
                'WPAD Exists?'      = $wpadrecord.'WPAD Exists?'
                'Current WPAD Type' = $wpadrecord.'WPAD Type'
                'Correct Type'      = $correctType
            }
        }

        $FailedWPADRecord += $AddToList
    }

    $FailedWPADRecord
}
function Test-BTZoneScopeContainer {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$ZoneScopeContainers
    )

    if ($null -eq $ZoneScopeContainers) {
        $ZoneScopeContainers = Get-BTZoneScopeContainer
    }

    $FailedZoneScopeContainerList = @()

    foreach ($zoneScopeContainer in $ZoneScopeContainers) {
        if ( (Get-ADObject -Filter * -SearchBase $zoneScopeContainer.'Zone Scope Container DN' -Server $zoneScopeContainer.Domain).Count -gt 0) {
            break
        }
        else {
            $AddToList = [PSCustomObject]@{
                'Domain'    = $zoneScopeContainer.Domain
                'Zone Name' = $zoneScopeContainer.'Zone Name'
                'Zone Type' = $zoneScopeContainer.'Zone Scope Container DN'
            }
        }

        $FailedZoneScopeContainerList += $AddToList
    }

    $FailedZoneScopeContainerList
}
function ConvertFrom-IdentityReference {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Object
    )

    $Principal = New-Object System.Security.Principal.NTAccount($Object)
    if ($Principal -match '^(S-1|O:)') {
        $SID = $Principal
    }
    else {
        $SID = ($Principal.Translate([System.Security.Principal.SecurityIdentifier])).Value
    }
    return $SID
}
function ConvertTo-IdentityReference {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $SID
    )

    $Principal = New-Object System.Security.Principal.SecurityIdentifier($SID)
    $IdentityReference = $Principal.Translate([System.Security.Principal.NTAccount]).Value
    $IdentityReference
}

function Invoke-BlueTuxedo {
    [CmdletBinding()]
    param (
        [string]$Forest = (Get-ADForest).Name,
        [string]$InputPath,
        [switch]$ShowSecurityDescriptors = $false,
        [switch]$Demo = $false
    )
    if ($Demo) {
        Clear-Host 
    }
    $Domains = Get-BTTarget -Forest $Forest -InputPath $InputPath

    Show-BTLogo -Version "v2024.7"

    # Get Data
    Write-Host 'Please hold. Collecting DNS data from the following domains:' -ForegroundColor Green
    Write-Host $Domains -ForegroundColor Yellow
    Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] ADI Zones"
    $ADIZones = Get-BTADIZone -Domains $Domains
    Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Conditional Forwarders"
    $ConditionalForwarders = Get-BTConditionalForwarder -Domains $Domains
    Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Dangling SPNs"
    $DanglingSPNs = Get-BTDanglingSPN -Domains $Domains
    Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] DNS Admins Memberships"
    $DnsAdminsMemberships = Get-BTDnsAdminsMembership -Domains $Domains
    Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] DNS Update Proxy Memberships"
    $DnsUpdateProxyMemberships = Get-BTDnsUpdateProxyMembership -Domains $Domains
    Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Dynamic Update Service Accounts"
    $DynamicUpdateServiceAccounts = Get-BTDynamicUpdateServiceAccount -Domains $Domains
    Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Forwarder Configuration"
    $ForwarderConfigurations = Get-BTForwarderConfiguration -Domains $Domains
    Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Global Query Blocklists"
    $GlobalQueryBlockLists = Get-BTGlobalQueryBlockList -Domains $Domains
    Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Non ADI Zones"
    $NonADIZones = Get-BTNonADIZone -Domains $Domains
    Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Query Resolution Policies"
    $QueryResolutionPolicys = Get-BTQueryResolutionPolicy -Domains $Domains
    Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Security Descriptors"
    $SecurityDescriptors = Get-BTSecurityDescriptor -Domains $Domains
    Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Socket Pool Sizes"
    $SocketPoolSizes = Get-BTSocketPoolSize -Domains $Domains
    Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Tombstoned Nodes"
    $TombstonedNodes = Get-BTTombstonedNode -Domains $Domains
    Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Wildcard Records"
    $WildcardRecords = Get-BTWildcardRecord -Domains $Domains
    Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] WPAD Records"
    $WPADRecords = Get-BTWPADRecord -Domains $Domains
    Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Zone Scopes"
    $ZoneScopes = Get-BTZoneScope -Domains $Domains
    Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Zone Scope Containers"
    $ZoneScopeContainers = Get-BTZoneScopeContainer -ADIZones $ADIZones
    Write-Host 'Finished collecting DNS data from the following domains:' -ForegroundColor Green
    Write-Host $Domains -ForegroundColor Yellow

    $CollectedData = @{
        'ADIZones'                     = $ADIZones
        'ConditionalForwarders'        = $ConditionalForwarders
        'DanglingSPNs'                 = $DanglingSPNs
        'DnsAdminsMemberships'         = $DnsAdminsMemberships
        'DnsUpdateProxyMemberships'    = $DnsUpdateProxyMemberships
        'DynamicUpdateServiceAccounts' = $DynamicUpdateServiceAccounts
        'ForwarderConfigurations'      = $ForwarderConfigurations
        'GlobalQueryBlockLists'        = $GlobalQueryBlockLists
        'NonADIZones'                  = $NonADIZones
        'QueryResolutionPolicys'       = $QueryResolutionPolicys
        'SecurityDescriptors'          = $SecurityDescriptors
        'SocketPoolSizes'              = $SocketPoolSizes
        'TombstonedNodes'              = $TombstonedNodes
        'WildcardRecords'              = $WildcardRecords
        'WPADRecords'                  = $WPADRecords
        'ZoneScopes'                   = $ZoneScopes
        'ZoneScopeContainers'          = $ZoneScopeContainers
    }

    # Display All Collected Data
    $show = Read-Host "Show all collected DNS data? [Y]/n"
    if (($show -eq 'y') -or ($show -eq '') -or ($null -eq $show) ) {
        if ($Demo) {
            Show-BTCollectedData -Demo @CollectedData
        }
        elseif ($ShowSecurityDescriptors) {
            Show-BTCollectedData -ShowSecurityDescriptors @CollectedData
        }
        elseif ($Demo -and $ShowSecurityDescriptors) {
            Show-BTCollectedData -ShowSecurityDescriptors -Demo @CollectedData
        }
        else {
            Show-BTCollectedData @CollectedData
        }
    }

    # Test Data
    if ($Demo) {
        Clear-Host 
    }
    Write-Host 'Currently testing collected DNS data to identify possible issues...' -ForegroundColor Green
    Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] ADI Legacy Zones"
    $TestedADILegacyZones = Test-BTADILegacyZone -ADIZones $ADIZones
    Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] ADI Insecure Update Zones"
    $TestedADIInsecureUpdateZones = Test-BTADIInsecureUpdateZone -ADIZones $ADIZones
    Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Dynamic Update Service Accounts"
    $TestedDynamicUpdateServiceAccounts = Test-BTDynamicUpdateServiceAccount -DynamicUpdateServiceAccounts $DynamicUpdateServiceAccounts
    Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Forwarder Configurations"
    $TestedForwarderConfigurations = Test-BTForwarderConfiguration -ForwarderConfigurations $ForwarderConfigurations
    Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Global Query Block Lists"
    $TestedGlobalQueryBlockLists = Test-BTGlobalQueryBlockList -GlobalQueryBlockLists $GlobalQueryBlockLists
    Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Security Descriptor ACE"
    $TestedSecurityDescriptorACEs = Test-BTSecurityDescriptorACE -SecurityDescriptors $SecurityDescriptors -DynamicUpdateServiceAccounts $DynamicUpdateServiceAccounts -Domains $Domains
    Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Security Descriptor Owner"
    $TestedSecurityDescriptorOwners = Test-BTSecurityDescriptorOwner -SecurityDescriptors $SecurityDescriptors -DynamicUpdateServiceAccounts $DynamicUpdateServiceAccounts -Domains $Domains
    Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Socket Pool Sizes"
    $TestedSocketPoolSizes = Test-BTSocketPoolSize -SocketPoolSizes $SocketPoolSizes
    Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Wildcard Records"
    $TestedWildcardRecords = Test-BTWildcardRecord -WildcardRecords $WildcardRecords
    Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] WPAD Records"
    $TestedWPADRecords = Test-BTWPADRecord -WPADRecords $WPADRecords
    Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Zone Scope Containers"
    $TestedZoneScopeContainers = Test-BTZoneScopeContainer -ZoneScopeContainers $ZoneScopeContainers
    Write-Host 'Finished testing collected DNS data to identify possible issues.`n' -ForegroundColor Green

    $TestedData = @{
        'ConditionalForwarders'              = $ConditionalForwarders
        'DanglingSPNs'                       = $DanglingSPNs
        'DnsAdminsMemberships'               = $DnsAdminsMemberships
        'DnsUpdateProxyMemberships'          = $DnsUpdateProxyMemberships
        'NonADIZones'                        = $NonADIZones
        'QueryResolutionPolicys'             = $QueryResolutionPolicys
        'TombstonedNodes'                    = $TombstonedNodes
        'ZoneScopes'                         = $ZoneScopes
        'TestedADILegacyZones'               = $TestedADILegacyZones
        'TestedADIInsecureUpdateZones'       = $TestedADIInsecureUpdateZones
        'TestedDynamicUpdateServiceAccounts' = $TestedDynamicUpdateServiceAccounts
        'TestedForwarderConfigurations'      = $TestedForwarderConfigurations
        'TestedGlobalQueryBlockLists'        = $TestedGlobalQueryBlockLists
        'TestedSecurityDescriptorACEs'       = $TestedSecurityDescriptorACEs
        'TestedSecurityDescriptorOwners'     = $TestedSecurityDescriptorOwners
        'TestedSocketPoolSizes'              = $TestedSocketPoolSizes
        'TestedWildcardRecords'              = $TestedWildcardRecords
        'TestedWPADRecords'                  = $TestedWPADRecords
        'TestedZoneScopeContainers'          = $TestedZoneScopeContainers
    }

    # Display All Tested Data
    $show = Read-Host "Show possible DNS issues in the environment? [Y]/n"
    if (($show -eq 'y') -or ($show -eq '') -or ($null -eq $show) ) {
        if ($Demo) {
            Show-BTTestedData -Demo  @TestedData
        }
        elseif ($ShowSecurityDescriptors) {
            Show-BTTestedData -ShowSecurityDescriptors @TestedData
        }
        elseif ($Demo -and $ShowSecurityDescriptors) {
            Show-BTTestedData -ShowSecurityDescriptors -Demo @TestedData
        }
        else {
            Show-BTTestedData @TestedData
        }
    }

    # Display Fixes
    $show = Read-Host "Show fixes for identified issues? [Y]/n"
    if (($show -eq 'y') -or ($show -eq '') -or ($null -eq $show) ) {
        if ($Demo) {
            Show-BTFixes -Demo @TestedData
        }
        elseif ($ShowSecurityDescriptors) {
            Show-BTFixes -ShowSecurityDescriptors @TestedData
        }
        elseif ($Demo -and $ShowSecurityDescriptors) {
            Show-BTFixes -ShowSecurityDescriptors -Demo @TestedData
        }
        else {
            Show-BTFixes @TestedData
        }
    }
}


# Export functions and aliases as required
Invoke-BlueTuxedo
