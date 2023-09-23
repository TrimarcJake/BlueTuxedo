function Get-ADIZone {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]
        $Domains
    )

    $ZoneList = @()
    foreach ($domain in $Domains) {
        $DNSServers = Resolve-DnsName -Type NS -Name $domain | Where-Object QueryType -eq 'A'
        foreach ($dnsServer in $DNSServers) {
            $Zones = Get-DnsServerZone -ComputerName $dnsServer.IP4Address | Where-Object { 
                ($_.IsAutoCreated -eq $false) -and 
                ($_.ZoneType -ne 'Forwarder') -and
                ($_.IsDsIntegrated -eq $true)
            }
            
            foreach ($zone in $Zones) {
                Write-Host $Zone
                $AddToList = [PSCustomObject]@{
                    'Server Name' = $dnsServer.Name
                    'Server IP'   = $dnsServer.IP4Address
                    'Zone Name'   = $zone.ZoneName
                    'Zone Type'   = $zone.ZoneType
                    'Is Reverse?' = $zone.IsReverseLookupZone
                }
                
                $ZoneList += $AddToList
            }
        }
    }

    $ZoneList
}