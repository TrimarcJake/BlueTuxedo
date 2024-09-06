function Get-BTNonADIZone {
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

    $ZoneList = @()

    foreach ($dnsServer in $script:DNSServers) {

        # Enumerate the zones on each DNS server.
        $Zones = Get-DnsServerZone -ComputerName $dnsServer.IPAddress | Where-Object {
            ($_.IsAutoCreated -eq $false) -and
            ($_.ZoneType -ne 'Forwarder') -and
            ($_.IsDsIntegrated -eq $false)
        }

        # Add zone and server details to the zone list.
        foreach ($zone in $Zones) {
            $AddToList = [PSCustomObject]@{
                'Server Name' = $dnsServer.Name
                'Server IP'   = $dnsServer.IPAddress
                'Zone Name'   = $zone.ZoneName
                'Zone Type'   = $zone.ZoneType
                'Is Reverse?' = $zone.IsReverseLookupZone
            }

            $ZoneList += $AddToList
        }
    }

    if ($ZoneList.Count -lt 1) {
        Write-Host 'No non-AD-integrated zones were found.'
    }
    # Return the ZoneList object
    $ZoneList
}
