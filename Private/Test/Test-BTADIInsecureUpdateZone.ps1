function Test-BTADIInsecureUpdateZone {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$ADIZones
    )

    if ($null -eq $ADIZones) {
        $ADIZones = Get-BTADIZone
    }

    $FailedADIZoneList = @()

    foreach ($adizone in $ADIZones) {
        if ( ($adizone.'Zone Type' -ne 'Stub') -and ($adizone.'Dynamic Update' -ne 'Secure') ) {
            $FailedADIZoneList += $adizone
        }
    }

    $FailedADIZoneList
}