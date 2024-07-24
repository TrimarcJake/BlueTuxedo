function Test-BTADILegacyZone {
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
        if ($adizone.'Zone Type' -eq 'Legacy') {
            [string]$domainDN = (Get-ADDomain $adizone.Domain).DistinguishedName
            try {
                $zoneDN = Get-ADobject -Identity "DC=$($adizone.'Zone Name'),CN=MicrosoftDNS,CN=System,$domainDN" -Server $adizone.Domain -Properties DistinguishedName -ErrorAction SilentlyContinue 
                $AddToList = [PSCustomObject]@{
                    'Domain'      = $adizone.Domain
                    'Zone Name'   = $adizone.'Zone Name'
                    'Zone Type'   = $adizone.'Zone Type'
                    'Is Reverse?' = $adizone.'Is Reverse?'
                    'Zone DN'     = $zoneDN
                }
            }
            catch {

            }
            
            $FailedADIZoneList += $AddToList
        }
    }

    $FailedADIZoneList
}