function Invoke-BlueTuxedo {
    [CmdletBinding()]
    param (
        [string]$Forest = (Get-ADForest).Name,
        [string]$InputPath
    )
    
    $Domains = Get-BTTarget -Forest $Forest -InputPath $InputPath

    # Get Data
    $ADIZones = Get-BTADIZone -Domains $Domains
    $ConditionalForwarders = Get-BTConditionalForwarder -Domains $Domains
    $DanglingSPNs = Get-BTDanglingSPN -Domains $Domains
    $DnsAdminsMemberships = Get-BTDnsAdminsMembership -Domains $Domains
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
    $TestedADIZones = Test-BTADIZone -ADIZones $ADIZones
    $TestedDynamicUpdateServiceAccounts = Test-BTDynamicUpdateServiceAccount -DynamicUpdateServiceAccounts $DynamicUpdateServiceAccounts
    $TestedForwarderConfigurations = Test-BTForwarderConfiguration -ForwarderConfigurations $ForwarderConfigurations
    $TestedGlobalQueryBlockLists = Test-BTGlobalQueryBlockList -GlobalQueryBlockLists $GlobalQueryBlockLists
    $TestedSecurityDescriptorACEs = Test-BTSecurityDescriptorACE -SecurityDescriptors $SecurityDescriptors -DynamicUpdateServiceAccounts $DynamicUpdateServiceAccounts -Domains $Domains
    $TestedSecurityDescriptorOwners = Test-BTSecurityDescriptorOwner -SecurityDescriptors $SecurityDescriptors -DynamicUpdateServiceAccounts $DynamicUpdateServiceAccounts -Domains $Domains
    $TestedSocketPoolSizes = Test-BTSocketPoolSize -SocketPoolSizes $SocketPoolSizes 
    $TestedWildcardRecords = Test-BTWildcardRecord -WildcardRecords $WildcardRecords
    $TestedWPADRecords = Test-BTWPADRecord -WPADRecords $WPADRecords
    $TestedZoneScopeContainers = Test-BTZoneScopeContainer -ZoneScopeContainers $ZoneScopeContainers

    # Generate Fixes

    # Display All Collected Data
    Show-BTCollectedData -ShowSecurityDescriptors
    
    # Display All Tested Data
    Show-BTTestedData -ShowSecurityDescriptors

    # Display Fixes
}