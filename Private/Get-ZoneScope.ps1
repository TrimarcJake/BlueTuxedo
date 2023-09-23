function Get-ZoneScope {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [array]
        $Domains
    )

    $ZoneScopeList = @()
    foreach ($domain in $Domains) {
        $DNSServers = Resolve-DnsName -Type NS -Name $domain | Where-Object QueryType -eq 'A'
        foreach ($dnsServer in $DNSServers) {
            $ZoneScopes = Get-DnsServerZone -ComputerName $dnsServer.IP4Address | Where-Object { 
                ($_.IsDsIntegrated -eq $true) -and
                ($_.IsReverseLookupZone -eq $false) -and
                ($_.ZoneName -ne 'TrustAnchors')
            } | Get-DnsServerZoneScope -ComputerName $dnsServer.IP4Address -ErrorAction Ignore

            if ($ZoneScopeList.'Server IP' -notcontains $dnsServer.IP4Address) {
                    foreach ($scope in $ZoneScopes) {
                        $AddToList = [PSCustomObject]@{
                        'Server Name'     = $dnsServer.Name
                        'Server IP'       = $dnsServer.IP4Address
                        'Zone Scope Name' = $scope.ZoneScope
                    }

                    $ZoneScopeList += $AddToList
                }
            }

        }
    }

    $ZoneScopeList
}