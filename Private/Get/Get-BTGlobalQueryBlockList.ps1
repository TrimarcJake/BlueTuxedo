function Get-BTGlobalQueryBlockList {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$Domains
    )

    if ($null -eq $Domains) {
        $Domains = Get-BTTarget
    }

    $GlobalQueryBlockListList = @()
    foreach ($domain in $Domains) {
        $DNSServers = Resolve-DnsName -Type NS -Name $domain | Where-Object QueryType -eq 'A'
        foreach ($dnsServer in $DNSServers) {
            [array]$GlobalQueryBlockList = Get-DnsServerGlobalQueryBlockList -ComputerName $dnsServer.IP4Address
            if ($GlobalQueryBlockListList.'Server IP' -notcontains $dnsServer.IP4Address) {
                $AddToList = [PSCustomObject]@{
                    'Server Name'   = $dnsServer.Name
                    'Server IP'     = $dnsServer.IP4Address
                    'Enabled?'      = $GlobalQueryBlockList.Enable
                    GQBL            = $GlobalQueryBlockList.List
                }
            }

            $GlobalQueryBlockListList += $AddToList
        }
    }

    $GlobalQueryBlockListList
}