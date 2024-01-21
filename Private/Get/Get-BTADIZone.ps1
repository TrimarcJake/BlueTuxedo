function Get-BTADIZone {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$Domains
    )

    if ($null -eq $Domains) {
        $Domains = Get-BTTarget
    }

    $Zones = @()
    $ZoneList = @()

    $Root = Get-ADRootDSE
    $RootNC = $Root.rootDomainNamingContext
    $Zones = Get-ADObject -Filter {objectClass -eq 'dNSZone'} -SearchBase "CN=MicrosoftDNS,DC=ForestDnsZones,$RootNC"
    
    foreach ($zone in $Zones) {
        $AddToList = [PSCustomObject]@{
            'Domain'         = (Get-ADForest).RootDomain
            'Zone Name'      = $zone.name
            'Zone Type'      = 'Forest-replicated'
            'Is Reverse?'    = ($zone.name -match '\.in-addr\.arpa$')
            'Dynamic Update' = $zone.DynamicUpdate
        }
        
        $ZoneList += $AddToList
    }

    foreach ($domain in $Domains) {
        $Zones = @()
        $domainDN = (Get-ADDomain -Identity $domain).distinguishedName

        foreach ($context in @('CN=System','DC=DomainDnsZones') ) {
            $Zones = Get-ADObject -Filter {objectClass -eq 'dNSZone'} -SearchBase "CN=MicrosoftDNS,$context,$domainDN" -Server $domain
            if ($context -eq 'CN=System') {
                $ZoneType = 'Legacy'
            }
            else {
                $ZoneType = 'Domain-replicated'
            }
            
            foreach ($zone in $Zones) {
                $AddToList = [PSCustomObject]@{
                    'Domain'         = $domain
                    'Zone Name'      = $zone.name
                    'Zone Type'      = $ZoneType
                    'Is Reverse?'    = ($zone.name -match '\.in-addr\.arpa$')
                    'Dynamic Update' = $zone.DynamicUpdate
                }
                
                $ZoneList += $AddToList
            }
        }
        
    }

    $ZoneList
}