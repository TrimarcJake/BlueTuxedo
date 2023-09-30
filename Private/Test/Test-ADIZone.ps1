function Test-ADIZone {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$ADIZones
    )

    $FailedADIZoneList = @()

    foreach ($adizone in $ADIZones) {
        [string]$domainDN = (Get-ADDomain $adizone.Domain).DistinguishedName
        try {
            $zoneDN = Get-ADobject -Identity "DC=$($adizone.'Zone Name'),CN=MicrosoftDNS,CN=System,$domainDN" -Server $adizone.Domain -Properties DistinguishedName -ErrorAction SilentlyContinue 
            $isLegacy = $true
        } catch {
            $isLegacy = $false
        }
        $AddToList = [PSCustomObject]@{
            'Domain'     = $adizone.Domain
            'Zone Name'  = $adizone.'Zone Name'
            'Zone Type'  = $adizone.'Zone Type'
            'Is Reverse?' = $adizone.'Is Reverse?'
            'Is Legacy?' = $isLegacy
            'Zone DN'    = $zoneDN
        }

        $FailedADIZoneList += $AddToList
    }

    $FailedADIZoneList
}