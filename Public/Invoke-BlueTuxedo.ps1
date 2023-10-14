function Invoke-BlueTuxedo {
    [CmdletBinding()]
    param (
        [string]$Forest = (Get-ADForest).Name,
        [string]$InputPath
    )
    
    $Domains = Get-Target -Forest $Forest -InputPath $InputPath

    # Get Data
    $ADIZones = Get-ADIZone -Domains $Domains
    $ConditionalForwarders = Get-ConditionalForwarder -Domains $Domains
    $DanglingSPNs = Get-DanglingSPN -Domains $Domains
    $DnsAdminsMemberships = Get-DnsAdminsMembership -Domains $Domains
    $DynamicUpdateServiceAccounts = Get-DynamicUpdateServiceAccount -Domains $Domains
    $ForwarderConfigurations = Get-ForwarderConfiguration -Domains $Domains
    $GlobalQueryBlockLists = Get-GlobalQueryBlockList -Domains $Domains
    $NonADIZones = Get-NonADIZone -Domains $Domains
    $QueryResolutionPolicys = Get-QueryResolutionPolicy -Domains $Domains
    $SecurityDescriptors = Get-SecurityDescriptor -Domains $Domains
    $SocketPoolSizes = Get-SocketPoolSize -Domains $Domains
    $TombstonedNodes = Get-TombstonedNode -Domains $Domains
    $WildcardRecords = Get-WildcardRecord -Domains $Domains
    $WPADRecords = Get-WPADRecord -Domains $Domains
    $ZoneScopes = Get-ZoneScope -Domains $Domains
    $ZoneScopeContainers = Get-ZoneScopeContainer -ADIZones $ADIZones

    # Test Data
    $TestedADIZones = Test-ADIZone -ADIZones $ADIZones
    $TestedDynamicUpdateServiceAccounts = Test-DynamicUpdateServiceAccount -DynamicUpdateServiceAccounts $DynamicUpdateServiceAccounts
    $TestedForwarderConfigurations = Test-ForwarderConfiguration -ForwarderConfigurations $ForwarderConfigurations
    $TestedGlobalQueryBlockLists = Test-GlobalQueryBlockList -GlobalQueryBlockLists $GlobalQueryBlockLists
    $TestedSecurityDescriptorACEs = Test-SecurityDescriptorACE -SecurityDescriptors $SecurityDescriptors -DynamicUpdateServiceAccounts $DynamicUpdateServiceAccounts -Domains $Domains
    $TestedSecurityDescriptorOwners = Test-SecurityDescriptorOwner -SecurityDescriptors $SecurityDescriptors -DynamicUpdateServiceAccounts $DynamicUpdateServiceAccounts -Domains $Domains
    $TestedSocketPoolSizes = Test-SocketPoolSize -SocketPoolSizes $SocketPoolSizes 
    $TestedWildcardRecords = Test-WildcardRecord -WildcardRecords $WildcardRecords
    $TestedWPADRecords = Test-WPADRecord -WPADRecords $WPADRecords
    $TestedZoneScopeContainers = Test-ZoneScopeContainer -ZoneScopeContainers $ZoneScopeContainers

    # Generate Fixes

    # Display All Collected Data
    Show-CollectedData -ShowSecurityDescriptors
    
    # Display All Tested Data
    Show-TestedData -ShowSecurityDescriptors

    # Display Fixes
}