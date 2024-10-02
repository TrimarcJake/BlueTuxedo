function Get-BTConditionalForwarder {
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

        # Enumerate the zones on each DNS server
        $Zones = Get-DnsServerZone -ComputerName $dnsServer.IPAddress | Where-Object {
            ( $_.IsAutoCreated -eq $false ) -and
            ( $_.ZoneType -eq 'Forwarder' ) -and
            ( $_.IsDsIntegrated -eq $true )
        }

        # Loop through each zone on the server
        foreach ($zone in $Zones) {
            $AddToList = [PSCustomObject]@{
                'Domain'    = $domain
                'Zone Name' = $zone.ZoneName
            }

            # Add the info to the ZoneList array
            $ZoneList += $AddToList
        }
    }

    if ($ZoneList.Count -lt 1) {
        Write-Host 'No conditional forward lookup zones were found.'
    }
    # Return the ZoneList object
    $ZoneList
}
