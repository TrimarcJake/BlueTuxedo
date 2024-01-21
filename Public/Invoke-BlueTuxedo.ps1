function Invoke-BlueTuxedo {
    [CmdletBinding()]
    param (
        [string]$Forest = (Get-ADForest).Name,
        [string]$InputPath,
        [switch]$ShowSecurityDescriptors = $false,
        [switch]$Demo = $false
    )
    if ($Demo) { Clear-Host }
    $Domains = Get-BTTarget -Forest $Forest -InputPath $InputPath

    Show-BTLogo -Version '2024.1'

    # Get Data
    Write-Host 'Please hold. Collecting DNS data from the following domains:' -ForegroundColor Green
    Write-Host $Domains -ForegroundColor Yellow
    $ADIZones = Get-BTADIZone -Domains $Domains
    $ConditionalForwarders = Get-BTConditionalForwarder -Domains $Domains
    $DanglingSPNs = Get-BTDanglingSPN -Domains $Domains
    $DnsAdminsMemberships = Get-BTDnsAdminsMembership -Domains $Domains
    $DnsUpdateProxyMemberships = Get-BTDnsUpdateProxyMembership -Domains $Domains
    $DynamicUpdateServiceAccounts = Get-BTDynamicUpdateServiceAccount -Domains $Domains
    $ForwarderConfigurations = Get-BTForwarderConfiguration -Domains $Domains
    $GlobalQueryBlockLists = Get-BTGlobalQueryBlockList -Domains $Domains
    $NonADIZones = Get-BTNonADIZone -Domains $Domains
    $QueryResolutionPolicys = Get-BTQueryResolutionPolicy -Domains $Domains
    $SecurityDescriptors = Get-BTSecurityDescriptor -Domains $Domains
    $SocketPoolSizes = Get-BTSocketPoolSize -Domains $Domains
    $TombstonedNodes = Get-BTTombstonedNode -Domains $Domains
    $WildcardRecords = Get-BTWildcardRecord -Domains $Domains
    $WPADRecords = Get-BTWPADRecord -Domains $Domains
    $ZoneScopes = Get-BTZoneScope -Domains $Domains
    $ZoneScopeContainers = Get-BTZoneScopeContainer -ADIZones $ADIZones

    $CollectedData = @{
        'ADIZones' = $ADIZones
        'ConditionalForwarders' = $ConditionalForwarders
        'DanglingSPNs' = $DanglingSPNs
        'DnsAdminsMemberships' = $DnsAdminsMemberships
        'DnsUpdateProxyMemberships' = $DnsUpdateProxyMemberships
        'DynamicUpdateServiceAccounts' = $DynamicUpdateServiceAccounts
        'ForwarderConfigurations' = $ForwarderConfigurations
        'GlobalQueryBlockLists' = $GlobalQueryBlockLists
        'NonADIZones' = $NonADIZones
        'QueryResolutionPolicys' = $QueryResolutionPolicys
        'SecurityDescriptors' = $SecurityDescriptors
        'SocketPoolSizes' = $SocketPoolSizes
        'TombstonedNodes' = $TombstonedNodes
        'WildcardRecords' = $WildcardRecords
        'WPADRecords' = $WPADRecords
        'ZoneScopes' = $ZoneScopes
        'ZoneScopeContainers' = $ZoneScopeContainers
    }

    # Display All Collected Data
    $show = Read-Host "Show all collected DNS data? [Y]/n"
    if (($show -eq 'y') -or ($show -eq '') -or ($null -eq $show) ) {
        if ($Demo) {
            Show-BTCollectedData -Demo @CollectedData
        } elseif ($ShowSecurityDescriptors) {
            Show-BTCollectedData -ShowSecurityDescriptors @CollectedData
        } elseif ($Demo -and $ShowSecurityDescriptors) {
            Show-BTCollectedData -ShowSecurityDescriptors -Demo @CollectedData
        } else {
            Show-BTCollectedData @CollectedData
        }
    }

    # Test Data
    if ($Demo) { Clear-Host }
    Write-Host 'Currently testing collected DNS data to identify possible issues...' -ForegroundColor Green
    $TestedADILegacyZones = Test-BTADILegacyZone -ADIZones $ADIZones
    $TestedADIInsecureUpdateZones = Test-BTADIInsecureUpdateZone -ADIZones $ADIZones
    $TestedDynamicUpdateServiceAccounts = Test-BTDynamicUpdateServiceAccount -DynamicUpdateServiceAccounts $DynamicUpdateServiceAccounts
    $TestedForwarderConfigurations = Test-BTForwarderConfiguration -ForwarderConfigurations $ForwarderConfigurations
    $TestedGlobalQueryBlockLists = Test-BTGlobalQueryBlockList -GlobalQueryBlockLists $GlobalQueryBlockLists
    $TestedSecurityDescriptorACEs = Test-BTSecurityDescriptorACE -SecurityDescriptors $SecurityDescriptors -DynamicUpdateServiceAccounts $DynamicUpdateServiceAccounts -Domains $Domains
    $TestedSecurityDescriptorOwners = Test-BTSecurityDescriptorOwner -SecurityDescriptors $SecurityDescriptors -DynamicUpdateServiceAccounts $DynamicUpdateServiceAccounts -Domains $Domains
    $TestedSocketPoolSizes = Test-BTSocketPoolSize -SocketPoolSizes $SocketPoolSizes 
    $TestedWildcardRecords = Test-BTWildcardRecord -WildcardRecords $WildcardRecords
    $TestedWPADRecords = Test-BTWPADRecord -WPADRecords $WPADRecords
    $TestedZoneScopeContainers = Test-BTZoneScopeContainer -ZoneScopeContainers $ZoneScopeContainers

    $TestedData = @{
        'ConditionalForwarders' = $ConditionalForwarders
        'DanglingSPNs' = $DanglingSPNs
        'DnsAdminsMemberships' = $DnsAdminsMemberships
        'DnsUpdateProxyMemberships' = $DnsUpdateProxyMemberships
        'NonADIZones' = $NonADIZones
        'QueryResolutionPolicys' = $QueryResolutionPolicys
        'TombstonedNodes' = $TombstonedNodes
        'ZoneScopes' = $ZoneScopes
        'TestedADILegacyZones' = $TestedADILegacyZones
        'TestedADIInsecureUpdateZones' = $TestedADIInsecureUpdateZones
        'TestedDynamicUpdateServiceAccounts' = $TestedDynamicUpdateServiceAccounts
        'TestedForwarderConfigurations' = $TestedForwarderConfigurations
        'TestedGlobalQueryBlockLists' = $TestedGlobalQueryBlockLists
        'TestedSecurityDescriptorACEs' = $TestedSecurityDescriptorACEs
        'TestedSecurityDescriptorOwners' = $TestedSecurityDescriptorOwners
        'TestedSocketPoolSizes' = $TestedSocketPoolSizes
        'TestedWildcardRecords' = $TestedWildcardRecords
        'TestedWPADRecords' = $TestedWPADRecords
        'TestedZoneScopeContainers' = $TestedZoneScopeContainers
    }
    
    # Display All Tested Data
    $show = Read-Host "Show possible DNS issues in the environment? [Y]/n"
    if (($show -eq 'y') -or ($show -eq '') -or ($null -eq $show) ) {
        if ($Demo) {
            Show-BTTestedData -Demo  @TestedData
        } elseif ($ShowSecurityDescriptors) {
            Show-BTTestedData -ShowSecurityDescriptors @TestedData
        } elseif ($Demo -and $ShowSecurityDescriptors) {
            Show-BTTestedData -ShowSecurityDescriptors -Demo @TestedData
        } else {
            Show-BTTestedData @TestedData
        }
    }

    # Display Fixes
    $show = Read-Host "Show fixes for identified issues? [Y]/n"
    if (($show -eq 'y') -or ($show -eq '') -or ($null -eq $show) ) {
        if ($Demo) {
            Show-BTFixes -Demo @TestedData
        } elseif ($ShowSecurityDescriptors) {
            Show-BTFixes -ShowSecurityDescriptors @TestedData
        } elseif ($Demo -and $ShowSecurityDescriptors) {
            Show-BTFixes -ShowSecurityDescriptors -Demo @TestedData
        } else {
            Show-BTFixes @TestedData
        }
    }
}