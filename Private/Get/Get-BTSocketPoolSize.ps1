function Get-BTSocketPoolSize {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$Domains,

        # Name of the DNS server[s] to exclude
        [Parameter()]
        [string[]]
        $Exclude
    )

    if ($null -eq $Domains) {
        $Domains = Get-BTTarget
    }

    if ($null -eq $script:DNSServers) {
        $script:DNSServers = Get-BTDnsServers -Domains $Domains -Exclude $Exclude
    }

    $SocketPoolSizeList = @()

    foreach ($dnsServer in $script:DNSServers) {

        # Enumerate the socket pool size on each DNS server.
        [int32]$SocketPoolSize = (Get-DnsServerSetting -ComputerName $dnsServer.IPAddress -All -WarningAction Ignore).SocketPoolSize
        if ($SocketPoolSizeList.'Server IP' -notcontains $dnsServer.IPAddress) {
            $AddToList = [PSCustomObject]@{
                'Server Name'      = $dnsServer.Name
                'Server IP'        = $dnsServer.IPAddress
                'Socket Pool Size' = $SocketPoolSize
            }
        }

        $SocketPoolSizeList += $AddToList
    }

    $SocketPoolSizeList
}
