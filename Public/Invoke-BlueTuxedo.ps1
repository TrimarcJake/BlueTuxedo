function Invoke-BlueTuxedo {
    [CmdletBinding()]
    param (
        [string]$Forest = (Get-ADForest).Name,
        [string]$InputPath
    )
    
    $Domains = Get-BTTarget -Forest $Forest -InputPath $InputPath

    Show-BTLogo -Version '2023.11'

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

    # Test Data
    Write-Host 'Currently testing collected DNS data to identify possible issues...' -ForegroundColor Green
    $TestedADILegacyZones = Test-BTADILegacyZone -ADIZones $ADIZones
    $TestedDynamicUpdateServiceAccounts = Test-BTDynamicUpdateServiceAccount -DynamicUpdateServiceAccounts $DynamicUpdateServiceAccounts
    $TestedForwarderConfigurations = Test-BTForwarderConfiguration -ForwarderConfigurations $ForwarderConfigurations
    $TestedGlobalQueryBlockLists = Test-BTGlobalQueryBlockList -GlobalQueryBlockLists $GlobalQueryBlockLists
    $TestedSecurityDescriptorACEs = Test-BTSecurityDescriptorACE -SecurityDescriptors $SecurityDescriptors -DynamicUpdateServiceAccounts $DynamicUpdateServiceAccounts -Domains $Domains
    $TestedSecurityDescriptorOwners = Test-BTSecurityDescriptorOwner -SecurityDescriptors $SecurityDescriptors -DynamicUpdateServiceAccounts $DynamicUpdateServiceAccounts -Domains $Domains
    $TestedSocketPoolSizes = Test-BTSocketPoolSize -SocketPoolSizes $SocketPoolSizes 
    $TestedWildcardRecords = Test-BTWildcardRecord -WildcardRecords $WildcardRecords
    $TestedWPADRecords = Test-BTWPADRecord -WPADRecords $WPADRecords
    $TestedZoneScopeContainers = Test-BTZoneScopeContainer -ZoneScopeContainers $ZoneScopeContainers


    # Display All Collected Data
    $show = Read-Host "Show all collected DNS data? [Y]/n"
    if (($show -eq 'y') -or ($show -eq '') -or ($null -eq $show) ) {
        Show-BTCollectedData
    }
    
    # Display All Tested Data
    $show = Read-Host "Show possible DNS issues in the environment? [Y]/n"
    if (($show -eq 'y') -or ($show -eq '') -or ($null -eq $show) ) {
        Show-BTTestedData
    }

    # Display Fixes
    $show = Read-Host "Show fixes for identified issues? [Y]/n"
    if (($show -eq 'y') -or ($show -eq '') -or ($null -eq $show) ) {
        Show-BTFixes
    }
}