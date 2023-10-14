function Get-ZoneScopeContainer {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [array]$ADIZones
    )

    $ZoneScopeContainerList = @()
    foreach ($adizone in $ADIZones) {
        [string]$domainDN = (Get-ADDomain $adizone.Domain).DistinguishedName
        try {
            $zoneScopeDN = Get-ADObject -Identity "CN=ZoneScopeContainer,DC=$($adizone.'Zone Name'),CN=MicrosoftDNS,DC=DomainDnsZones,$domainDN" -Server $adizone.Domain -Properties DistinguishedName -SilentlyContinue
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