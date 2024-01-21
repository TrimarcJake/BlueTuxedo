function Repair-BTTestedADILegacyZone {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$TestedADILegacyZones,
        [switch]$Run = $false
    )

    if ($null -eq $TestedADILegacyZones) {
        $TestedADILegacyZones = Test-BTADILegacyZone
    }

    if ($Run) {
        foreach ($adizone in $TestedADILegacyZones) {
            # $DomainReplicatedZonePartition = "DomainDnsZones.$adizone.Domain"
            $ForestReplicatedZonePartition = "ForestDnsZones.$(Get-ADForest $($adizone.Domain))"
            dnscmd $adizone.Domain /ZoneChangeDirectoryPartition $adizone.'Zone Name' $ForestReplicatedZonePartition
        }
    } else {
        foreach ($adizone in $TestedADILegacyZones) {
            Write-Host "Run the following code block to convert the $($adizone.Domain) Zone from a Legacy (Windows 2000 compatible Zone) to a Forest-replicated Zone." -ForegroundColor Green
            Write-Host @"
`$ForestReplicatedZonePartition = 'ForestDnsZones.$(Get-ADForest $($adizone.Domain))'
dnscmd $($adizone.Domain) /ZoneChangeDirectoryPartition $($adizone.'Zone Name') `$ForestReplicatedZonePartition

"@
        }
    }
}