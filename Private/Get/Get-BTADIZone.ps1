function Get-BTADIZone {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$Domains
    )

    if ($null -eq $Domains) {
        $Domains = Get-BTTarget
    }

    $ZoneList = @()
    foreach ($domain in $Domains) {
        $Zones = Get-DnsServerZone -ComputerName $domain | Where-Object { 
            ($_.IsAutoCreated -eq $false) -and 
            ($_.ZoneType -ne 'Forwarder') -and
            ($_.IsDsIntegrated -eq $true)
        }
        
        foreach ($zone in $Zones) {
            $AddToList = [PSCustomObject]@{
                'Domain'         = $domain
                'Zone Name'      = $zone.ZoneName
                'Zone Type'      = $zone.ZoneType
                'Is Reverse?'    = $zone.IsReverseLookupZone
                'Dynamic Update' = $zone.DynamicUpdate
            }
            
            $ZoneList += $AddToList
        }
    }

    $ZoneList
}