function Get-BTDnsUpdateProxyMembership {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$Domains
    )

    if ($null -eq $Domains) {
        $Domains = Get-BTTarget
    }

    $ForestDnsUpdateProxyMembership = @()

    foreach ($domain in $Domains) {
        $domainDnsUpdateProxyMembership = Get-ADGroupMember 'DnsUpdateProxy' -Recursive -Server $domain
        # TODO Capture nested members with non-standard PGID
        foreach ($member in $domainDnsUpdateProxyMembership) {
            $principal = [PSCustomObject]@{
                'Group Domain' = $domain
                'Member Name'  = $member.Name
                'Member Distinguished Name' = $member.distinguishedName
            }
            if ($ForestDnsUpdateProxyMembership.distinguishedName -notcontains $member.distinguishedName) {
                $ForestDnsUpdateProxyMembership += $principal
            }
        }
    }

    $ForestDnsUpdateProxyMembership
}