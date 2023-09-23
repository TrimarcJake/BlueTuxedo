function Invoke-BlueTuxedo {
    # param(
    #     $Forest
    # )
    $Domains = (Get-ADForest).Domains
    Get-ADIZone -Domains $Domains
    Get-ConditionalForwarder -Domains $Domains
    # Get-DACL -Domains $Domains
    Get-DanglingSPN -Domains $Domains
    Get-DnsAdminsMembership -Domains $Domains
    Get-DynamicUpdateServiceAccount -Domains $Domains
    Get-ForwarderConfiguration -Domains $Domains
    Get-GlobalQueryBlockList -Domains $Domains
    Get-NonADIZone -Domains $Domains
    Get-QueryResolutionPolicy -Domains $Domains
    Get-SocketPoolSize -Domains $Domains
    Get-TombstonedNode -Domains $Domains
    Get-WildcardRecord -Domains $Domains
    Get-WPADRecord -Domains $Domains
    Get-ZoneScope -Domains $Domains
}