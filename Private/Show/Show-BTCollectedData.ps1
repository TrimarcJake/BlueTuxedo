function Show-BTCollectedData {
    [CmdletBinding()]
    param (
        [switch]$ShowSecurityDescriptors = $false,
        [switch]$Demo,
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
        [string]$Section = 'All'
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
        'Section' = 'Friendly Name'
        'ADIZones' = 'All ADI Zones'
        'ConditionalForwarders' = 'All Conditional Forwarders'
        'DanglingSPNs' = 'All Dangling SPNs'
        'DnsAdminsMemberships' = 'DnsAdmins Memberships'
        'DnsUpdateProxyMemberships' = 'DnsUpdateProxy Memberships'
        'DynamicUpdateServiceAccounts' = 'Dynamic Update Service Account Configuration by DNS Server'
        'ForwarderConfigurations' = 'Forwarder Configurations by DNS Server'
        'GlobalQueryBlockLists' = 'All Global Query Block Lists'
        'NonADIZones' = 'All Non-ADI Zones'
        'QueryResolutionPolicys' = 'All Query Resolution Policies'
        'SecurityDescriptors' = 'All Security Descriptors'
        'SocketPoolSizes' = 'Socket Pool Size Configuration by DNS Server'
        'TombstonedNodes' = 'All Tombstoned Nodes'
        'WildcardRecords' = 'Wildcard Record Configuration by Domain'
        'WPADRecords' = 'WPAD Record Configuration by Domain'
        'ZoneScopes' = 'All Zone Scopes'
        'ZoneScopeContainers' = 'All Zone Scope Containers'
    }

    if ($ShowSecurityDescriptors) {
        $Sections += 'SecurityDescriptors'
    }
    
    if ($Section = 'All') {
        foreach ($entry in $Sections) {
            $Title = $TitleHashtable[$entry]
            if ($Demo) { Clear-Host }
            Write-Host "/--------------- $Title ---------------\" -ForegroundColor Green
            (Get-Variable $entry).Value | Format-List
            Write-Host "\--------------- $Title ---------------/" -ForegroundColor Green
            Read-Host "Press Enter to load the next section"
        }
    } else {
        $Title = $TitleHashtable[$Section]
        if ($Demo) { Clear-Host }
        Write-Host "/--------------- $Title ---------------\" -ForegroundColor Green
        (Get-Variable $Section).Value
        Write-Host "\--------------- $Title ---------------/" -ForegroundColor Green
    }
}