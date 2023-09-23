function Get-SocketPoolSize {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [array]
        $Domains
    )

    $SocketPoolSizeList = @()
    foreach ($domain in $Domains) {
        $DNSServers = Resolve-DnsName -Type NS -Name $domain | Where-Object QueryType -eq 'A'
        foreach ($dnsServer in $DNSServers) {
            [int32]$SocketPoolSize = (Get-DnsServerSetting -ComputerName $dnsServer.IP4Address -All -WarningAction Ignore).SocketPoolSize
            if ($SocketPoolSizeList.'Server IP' -notcontains $dnsServer.IP4Address) {
                $AddToList = [PSCustomObject]@{
                    'Server Name'         = $dnsServer.Name
                    'Server IP'           = $dnsServer.IP4Address
                    'Socket Pool Size'    = $SocketPoolSize
                }
            }

            $SocketPoolSizeList += $AddToList
        }
    }

    $SocketPoolSizeList
}