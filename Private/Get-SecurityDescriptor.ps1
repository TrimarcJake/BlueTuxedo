function Get-SecurityDescriptor {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [array]
        $Domains
    )

    $ObjectACEList = @()
    $ForestDN = (Get-ADRootDSE).rootDomainNamingContext
    foreach ($domain in $Domains) {
        $DomainDN = (Get-ADDomain $domain).DistinguishedName
        $DomainNetBIOSName = (Get-ADDomain $domain).NetBIOSName
        if ($ForestDN -eq $DomainDN) {
            $Locations = 'DC=ForestDnsZones','DC=DomainDnsZones','CN=MicrosoftDNS,CN=System'
            New-PSDrive -Name $DomainNetBIOSName -PSProvider ActiveDirectory -Server $domain -root "//RootDSE/"
            foreach ($location in $Locations) {
                $Objects = Get-ADObject -Filter * -SearchBase "$location,$DomainDN" -Server $domain
                foreach ($object in $Objects) {
                    $ObjectACEList += Get-ACL "AD:$($object.DistinguishedName)"
                }
            }
        } else {
            New-PSDrive -Name $DomainNetBIOSName -PSProvider ActiveDirectory -Server $domain -root "//RootDSE/"
            $Objects = Get-ADObject -Filter * -SearchBase "DC=DomainDnsZones,$DomainDN" -Server $domain
            foreach ($object in $Objects) {
                $ObjectACEList += Get-ACL "AD:$($object.DistinguishedName)"
            }
        }
    }

    # $ObjectACEList
}