function Test-BTADIZoneInsecureUpdate {
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
        # [string]$domainDN = (Get-ADDomain $adizone.Domain).DistinguishedName
        # try {
        #     $zoneDN = Get-ADobject -Identity "DC=$($adizone.'Zone Name'),CN=MicrosoftDNS,CN=System,$domainDN" -Server $adizone.Domain -Properties DistinguishedName -ErrorAction SilentlyContinue 
        #     $AddToList = [PSCustomObject]@{
        #         'Domain'      = $adizone.Domain
        #         'Zone Name'   = $adizone.'Zone Name'
        #         'Zone Type'   = $adizone.'Zone Type'
        #         'Is Reverse?' = $adizone.'Is Reverse?'
        #         'Zone DN'     = $zoneDN
        #     }
        # } catch {

        # }

        if ( ($adizone.'Zone Type' -ne 'Stub') -and ($adizone.'Dynamic Update' -ne 'Secure') ) {
            $FailedADIZoneList += $adizone
        }
    }

    $FailedADIZoneList
}