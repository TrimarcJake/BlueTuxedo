function Get-GlobalQueryBlockList {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [array]
        $Domains
    )

    $GlobalQueryBlockListList = @()
    foreach ($domain in $Domains) {
        $DNSServers = Resolve-DnsName -Type NS -Name $domain | Where-Object QueryType -eq 'A'
        foreach ($dnsServer in $DNSServers) {
            [array]$GlobalQueryBlockList = Get-DnsServerGlobalQueryBlockList -ComputerName $dnsServer.IP4Address
            Write-Host "GQBL: $($GlobalQueryBlockList.List)";pause
            if ($GlobalQueryBlockListList.'Server IP' -notcontains $dnsServer.IP4Address) {
                $AddToList = [PSCustomObject]@{
                    'Server Name'   = $dnsServer.Name
                    'Server IP'     = $dnsServer.IP4Address
                    GQBL    = $GlobalQueryBlockList.List
                }
            }

            $GlobalQueryBlockListList += $AddToList
        }
    }

    $GlobalQueryBlockListList
}