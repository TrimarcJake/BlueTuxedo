function Get-ZoneScopeContainer {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [array]$ADIZones
    )

    $ZoneScopeContainerList = @()
    foreach ($adizone in $ADIZones) {
        [string]$domainDN = (Get-ADDomain $adizone.Domain).DistinguishedName
        # try {
            "CN=ZoneScopeContainer,DC=$($adizone.'Zone Name'),CN=MicrosoftDNS,CN=System,$domainDN"
            $zoneScopeDN = Get-ADObject -Identity "CN=ZoneScopeContainer,DC=$($adizone.'Zone Name'),CN=MicrosoftDNS,CN=System,$domainDN" -Server $adizone.Domain -Properties DistinguishedName # -ErrorAction SilentlyContinue 
            $zoneScopeDN
        # } catch {

        # }
    }

    $ZoneScopeContainerList
}