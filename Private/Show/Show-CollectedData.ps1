function Show-CollectedData {
    [CmdletBinding()]
    param (
        [ValidateSet(
            'All',
            'ADIZones',
            'ConditionalForwarders',
            'DanglingSPNs',
            'DnsAdminsMemberships',
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
        [switch]$ShowSecurityDescriptors = $false
    )

    $Sections = @(
        'ADIZones',
        'ConditionalForwarders',
        'DanglingSPNs',
        'DnsAdminsMemberships',
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
        'DnsAdminsMemberships' = 'DnsAdmins Memberships (per-domain)'
        'DynamicUpdateServiceAccounts' = 'Dynamic Update Service Accounts'
        'ForwarderConfigurations' = 'Forwarder Configurations'
        'GlobalQueryBlockLists' = 'Global Query Block Lists'
        'NonADIZones' = 'Non-ADI Zones'
        'QueryResolutionPolicys' = 'Query Resolution Policies'
        'SecurityDescriptors' = 'Security Descriptors'
        'SocketPoolSizes' = 'Socket Pool Sizes'
        'TombstonedNodes' = 'Tombstoned Nodes'
        'WildcardRecords' = 'Wildcard Records'
        'WPADRecords' = 'WPAD Records'
        'ZoneScopes' = 'Zone Scopes'
        'ZoneScopeContainers' = 'Zone Scope Containers'
    }

    if ($ShowSecurityDescriptors) {
        $Sections += 'SecurityDescriptors'
    }
    
    if ($Section = 'All') {
        foreach ($entry in $Sections) {
            $Title = $TitleHashtable[$entry]
            Write-Host "/--------------- $Title ---------------\" -ForegroundColor Green
            (Get-Variable $entry).Value | Format-List
            Write-Host "\--------------- $Title ---------------/" -ForegroundColor Green
            Read-Host "Press Enter to load the next section."
        }
    } else {
        $Title = $TitleHashtable[$Section]
        Write-Host "/--------------- $Title ---------------\" -ForegroundColor Green
        (Get-Variable $Section).Value
        Write-Host "\--------------- $Title ---------------/" -ForegroundColor Green
    }
}