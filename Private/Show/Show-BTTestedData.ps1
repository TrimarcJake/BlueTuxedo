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
        'Section' = 'Friendly Name'
        'ConditionalForwarders' = 'All Conditional Forwarders' 
        'DanglingSPNs' = 'All Dangling SPNs' 
        'DnsAdminsMemberships' = 'DnsAdmins Membership (per-domain)' 
        'DnsUpdateProxyMemberships' = 'DnsUpdateProxy Membership (per-domain)'
        'NonADIZones' = 'All Non-ADI Zones' 
        'QueryResolutionPolicys' = 'All Query Resolution Policies' 
        'TombstonedNodes' = 'All Tombstoned Nodes'
        'ZoneScopes' = 'Tested Zone Scopes'
        'TestedADILegacyZones' = 'Legacy ADI Zones'
        'TestedADIInsecureUpdateZones' = 'ADI Zones not configured for Secure Updates'
        'TestedDynamicUpdateServiceAccounts' = 'DHCP Servers not configured to use Dynamic Update Service Accounts' 
        'TestedForwarderConfigurations' = 'All Configured Forwarders' 
        'TestedGlobalQueryBlockLists' = 'All Global Query Block Lists' 
        'TestedSecurityDescriptorACEs' = 'Possibly Dangerous ACEs on DNS Objects' 
        'TestedSecurityDescriptorOwners' = 'Possibly Dangerous Owners of DNS Objects' 
        'TestedSocketPoolSizes' = 'Socket Pool Sizes Less Than Maximum' 
        'TestedWildcardRecords' = 'Missing or Invalid Wildcard Records' 
        'TestedWPADRecords' = 'Missing or Invalid WPAD Records'
        'TestedZoneScopeContainers' = 'Empty Zone Scope Containers' 
    }

    $DescriptionHashtable = @{
        'Section' = "Description"
        'ConditionalForwarders' = "Check this list of conditional forwarders.`nAre they still in use?"
        'DanglingSPNs' = "Dangling SPNs are Service Principal Names where the 'Host' portion of the SPN does not resolve to an IP address.`nDangling SPNs can be used by an attacker to coerce Kerberos authentication."
        'DnsAdminsMemberships' = "The DnsAdmins group remains incredibly powereful.`nKeep this group empty if possible.`nIf not possible, ensure the members are protected like Tier 0 assets."
        'DnsUpdateProxyMemberships' = "Members of DnsUpdateProxy group can update ADI DNS records regardless of existing ownership.`nWhile doing so, they grant Authenticated Users the right to modify the DNS record.`nThis group should be kept empty if possible."
        'NonADIZones' = "Non-ADI Zones have their information stored on each DNS server/DC instead of in AD.`nNon-ADI Zones create inconsistency across resolvers."
        'QueryResolutionPolicys' = "Query Resolution Policies are configured per-server and do not appear in the DNS snap-in.`nAudit these entries to ensure they are apppropriate."
        'TombstonedNodes' = "Tombstoned Nodes can be updated by any security principal in the forest.`nRemove these nodes."
        'ZoneScopes' = "Zone Scopes can be used to create a fully ADI split-brain DNS.`nEnsure these scopes are appropriate for your environment"
        'TestedADILegacyZones' = "ADI Zones can be replicated in 3 ways: forest-replicated, domain-replicated, and Windows 2000-compatible mode (aka Legacy).`nLegacy Zones are not protected in the same manner as other zones and inherit ACEs from the domain root.`nThese zones should be converted to one of the other types."
        'TestedADIInsecureUpdateZones' = "[TODO]"
        'TestedDynamicUpdateServiceAccounts' = "Out-of-the-box, AD-joined computers that receive an IP address from a Windows DHCP server can create and update their own DNS nodes.`nA more secure method of creating these nodes is to configure a Dynamic Update Service Account on each DHCP server.`nWhen configured, Dynamic Update Service Accounts can be used to create DNS records on behalf of computers.`nThis makes auditing DACLs easier.`n`nThe following DNS servers do not use a Dynamic Update Service Account:"
        'TestedForwarderConfigurations' = "When a local DNS server cannot resolve a request, they send a request to a Forwarder.`nCheck the following list to ensure the Forwarders are approriate for your environment."
        'TestedGlobalQueryBlockLists' = "Despite the name, Global Query Block Lists are configured per-server.`nEach GQBL contains a list of names that the DNS server will not resolve.`nThis list should contain the 'wpad' and 'isatap' records at a minimum."
        'TestedSecurityDescriptorACEs' = "The following DNS objects have possibly dangerous Access Control Entries.`nNote: if Dynamic Update Service Accounts are not configured on each DHCP server, this section will be very noisy."
        'TestedSecurityDescriptorOwners' = "The following DNS objects have possibly dangerous Owners.`nNote: if Dynamic Update Service Accounts are not configured on each DHCP server, this section will be very noisy."
        'TestedSocketPoolSizes' = "When making requests to Forwarders, DNS servers randomize their source ports to minimize AITM attacks.`nThe number of ports used is configured on each DNS Server via the Socket Pool Size value.`nBy default, this is 2500 ports, but the maximum is 10,000.`nConfigure each DNS server to use the maximum value."
        'TestedWildcardRecords' = "If a Wildcard Record does not exist in a domain, an attacker can create one which points at a device they control.`nAny DNS requests that do not match an existing DNS entry will resolve to the IP of the attacker-controlled machine."
        'TestedWPADRecords' = "WPAD is used to allow clients to auto-discover web proxy servers in their environment.`nIf a WPAD Record does not exist in a domain, an attacker can create one which points at a device they control.`nThis configuration could redirect all web traffic to the attacker-controller machine"
        'TestedZoneScopeContainers' = "Zone Scope Containers hold Zone Scopes.`nIf a Zone Scope Container is empty, this may be an indicator of fuckery (IOF)."
    }

    if ($ShowSecurityDescriptors) {
        $Sections += 'TestedSecurityDescriptorACEs','TestedSecurityDescriptorOwners'
    }
    
    if ($Section = 'All') {
        foreach ($entry in $Sections) {
            $Title = $TitleHashtable[$entry]
            $Description = $DescriptionHashtable[$entry]
            if ($null -ne (Get-Variable $entry).Value) {
                if ($Demo) { Clear-Host }
                Write-Host "/--------------- $Title ---------------\" -ForegroundColor Red
                Write-Host $Description
                (Get-Variable $entry).Value | Format-List
                Write-Host "\--------------- $Title ---------------/" -ForegroundColor Red
                Read-Host "Press Enter to load the next section"
            }
        }
    } else {
        $Title = $TitleHashtable[$Section]
        $Description = $DescriptionHashtable[$Section]
        if ($Demo) { Clear-Host }
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