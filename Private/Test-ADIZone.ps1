function Test-ADIZone {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$ADIZones
    )

    $FailedADIZoneList = @()

    foreach ($adizone in $ADIZones) {
        [string]$domainDN = (Get-ADDomain $adizone.Domain).DistinguishedName
        $legacyADIZoneDN = "DC=$($adizone.'Zone Name'),CN=MicrosoftDNS,CN=System,$domainDN"
        try {
            $zoneDN = Get-ADobject -Identity $legacyADIZoneDN -Server $adizone.Domain -Properties DistinguishedName -ErrorAction SilentlyContinue 
            $AddToList = [PSCustomObject]@{
                'Domain' = $adizone.Domain
                'Zone Name'   = $adizone.'Zone Name'
                'Zone Type'   = $adizone.'Zone Type'
                'Zone DN'     = $zoneDN
            }
            $FailedADIZoneList += $AddToList
        } catch {
        }
    }

    $FailedADIZoneList
}