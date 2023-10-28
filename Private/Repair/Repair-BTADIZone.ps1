function Repair-BTADIZone {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$ADIZones,
        [switch]$Run = $false
    )

    if ($null -eq $ADIZones) {
        $ADIZones = Get-BTADIZone
    }

    if ($Run) {
        foreach ($adizone in $ADIZones) {
            dnscmd $adizone.Domain /ZoneChangeDirectoryPartition $adizone.'Zone Name' [INSERT FOREST/DOMAIN-REPLICATE ZONE]
        }
    } else {
        foreach ($adizone in $ADIZones) {
            Write-Host "DESCRIPTION OF CODE BLOCK" -ForegroundColor Green
            Write-Host @"
CODE BLOCK

"@
        }
    }
}