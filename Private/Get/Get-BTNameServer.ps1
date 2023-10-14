function Get-BTNameServer {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$Domains
    )

    if ($null -eq $Domains) {
        $Domains = Get-BTTarget
    }

    $NameServerList = @()
    foreach ($domain in $Domains) {
        $DNSServers = Resolve-DnsName -Type NS -Name $domain | Where-Object QueryType -eq 'A'
        foreach ($dnsServer in $DNSServers) {
            if ($NameServerList.'Server IP' -notcontains $dnsServer.IP4Address) {
                $AddToList = [PSCustomObject]@{
                    'Server Name'   = $dnsServer.Name
                    'Server IP'     = $dnsServer.IP4Address
                }
            }

            $NameServerList += $AddToList
        }
    }

    $NameServerList
}