function Get-BTZoneScope {
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
        $script:DNSServers = Get-BTDnsServer -Domains $Domains -Exclude $Exclude
    }

    $ZoneScopeList = @()

    foreach ($dnsServer in $script:DNSServers) {

        # Enumerate the zone scopes on each DNS server
        $ZoneScopes = Get-DnsServerZone -ComputerName $dnsServer.IPAddress | Where-Object {
            ($_.IsDsIntegrated -eq $true) -and
            ($_.IsReverseLookupZone -eq $false) -and
            ($_.ZoneName -ne 'TrustAnchors')
        } | Get-DnsServerZoneScope -ComputerName $dnsServer.IPAddress -ErrorAction Ignore

        if ($ZoneScopeList.'Server IP' -notcontains $dnsServer.IPAddress) {
            foreach ($scope in $ZoneScopes) {
                $AddToList = [PSCustomObject]@{
                    'Server Name'     = $dnsServer.Name
                    'Server IP'       = $dnsServer.IPAddress
                    'Zone Scope Name' = $scope.ZoneScope
                }

                $ZoneScopeList += $AddToList
            }
        }

    }

    $ZoneScopeList
}
