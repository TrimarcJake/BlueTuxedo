function Get-BTZoneScopeContainer {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$ADIZones
    )

    if ($null -eq $ADIZones) {
        $ADIZones = Get-BTADIZone
    }

    $ZoneScopeContainerList = @()
    foreach ($adizone in $ADIZones) {
        [string]$domainDN = (Get-ADDomain $adizone.Domain).DistinguishedName
        try {
            $zoneScopeDN = Get-ADObject -Identity "CN=ZoneScopeContainer,DC=$($adizone.'Zone Name'),CN=MicrosoftDNS,DC=DomainDnsZones,$domainDN" -Server $adizone.Domain -Properties DistinguishedName -ErrorAction SilentlyContinue
            $AddToList = [PSCustomObject]@{
                Domain                    = $adizone.Domain
                'Zone Name'               = $adizone.'Zone Name'
                'Zone Scope Container DN' = $zoneScopeDN
            }
            $ZoneScopeContainerList += $AddToList
        } catch {

        }
    }

    $ZoneScopeContainerList
}