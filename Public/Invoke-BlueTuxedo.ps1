function Invoke-BlueTuxedo {
    [CmdletBinding()]
    param (
        [string]$Forest = (Get-ADForest).Name,
        [string]$InputPath
    )
    Get-Target -Forest $Forest -InputPath $InputPath
    Get-ADIZone -Domains $Domains
    Get-ConditionalForwarder -Domains $Domains
    Get-DanglingSPN -Domains $Domains
    Get-DnsAdminsMembership -Domains $Domains
    Get-DynamicUpdateServiceAccount -Domains $Domains
    Get-ForwarderConfiguration -Domains $Domains
    Get-GlobalQueryBlockList -Domains $Domains
    Get-NonADIZone -Domains $Domains
    Get-QueryResolutionPolicy -Domains $Domains
    Get-SecurityDescriptor -Domains $Domains
    Get-SocketPoolSize -Domains $Domains
    Get-TombstonedNode -Domains $Domains
    Get-WildcardRecord -Domains $Domains
    Get-WPADRecord -Domains $Domains
    Get-ZoneScope -Domains $Domains
}