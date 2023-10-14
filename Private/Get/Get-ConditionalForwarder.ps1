function Get-ConditionalForwarder {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$Domains
    )

    if ($null -eq $Domains) {
        $Domains = Get-Target
    }

    $ZoneList = @()
    foreach ($domain in $Domains) {
        $DNSServers = Resolve-DnsName -Type NS -Name $domain | Where-Object QueryType -eq 'A'
        foreach ($dnsServer in $DNSServers) {
            $Zones = Get-DnsServerZone -ComputerName $dnsServer.IP4Address | Where-Object { 
                ($_.IsAutoCreated -eq $false) -and 
                ($_.ZoneType -eq 'Forwarder') -and
                ($_.IsDsIntegrated -eq $true)
            }
            
            foreach ($zone in $Zones) {
                $AddToList = [PSCustomObject]@{
                    'Domain' = $domain
                    'Zone Name'   = $zone.ZoneName
                }
                
                $ZoneList += $AddToList
            }
        }
    }

    $ZoneList
}