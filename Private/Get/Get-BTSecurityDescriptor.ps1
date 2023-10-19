function Get-BTSecurityDescriptor {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$Domains
    )

    if ($null -eq $Domains) {
        $Domains = Get-BTTarget
    }

    $ObjectACLList = @()
    $ForestDN = (Get-ADRootDSE).rootDomainNamingContext
    foreach ($domain in $Domains) {
        $DomainDN = (Get-ADDomain $domain).DistinguishedName
        $DomainNetBIOSName = (Get-ADDomain $domain).NetBIOSName
        $Locations = @()
        if ($ForestDN -eq $DomainDN) {
            $Locations = 'DC=ForestDnsZones','DC=DomainDnsZones','CN=MicrosoftDNS,CN=System'
        } else {
            $Locations = 'DC=DomainDnsZones'
        }
        New-PSDrive -Name $DomainNetBIOSName -PSProvider ActiveDirectory -Server $domain -root "//RootDSE/" | Out-Null
        $Objects = @()
        foreach ($location in $Locations) {
            $Objects = Get-ADObject -Filter * -SearchBase "$location,$DomainDN" -Server $domain
            foreach ($object in $Objects) {
                $AddToList = Get-ACL "$($DomainNetBIOSName):$($object.DistinguishedName)"
                $AddToList | Add-Member NoteProperty -Name Name -Value $object.Name
                $AddToList | Add-Member NoteProperty -Name DistinguishedName -Value $object.DistinguishedName
                
                $ObjectACLList += $AddToList
            }
        }
    }

    $ObjectACLList
}