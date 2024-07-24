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
