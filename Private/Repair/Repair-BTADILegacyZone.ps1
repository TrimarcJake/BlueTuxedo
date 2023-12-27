function Repair-BTADILegacyZone {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$ADIZones,
        [switch]$Run = $false
    )

    if ($null -eq $ADIZones) {
        $ADIZones = Test-BTADILegacyZone
    }

    if ($Run) {
        foreach ($adizone in $ADIZones) {
            # $DomainReplicatedZonePartition = "DomainDnsZones.$adizone.Domain"
            $ForestReplicatedZonePartition = "ForestDnsZones.$(Get-ADForest $($adizone.Domain))"
            dnscmd $adizone.Domain /ZoneChangeDirectoryPartition $adizone.'Zone Name' $ForestReplicatedZonePartition
        }
    } else {
        foreach ($adizone in $ADIZones) {
            Write-Host "Run the following code block to convert the $($adizone.Domain) Zone from a Legacy (Windows 2000 compatible Zone) to a Forest-replicated Zone." -ForegroundColor Green
            Write-Host @"
`$ForestReplicatedZonePartition = 'ForestDnsZones.$(Get-ADForest $($adizone.Domain))'
dnscmd $($adizone.Domain) /ZoneChangeDirectoryPartition $($adizone.'Zone Name') `$ForestReplicatedZonePartition

"@
        }
    }
}