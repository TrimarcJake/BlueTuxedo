function Get-DnsAdminsMembership {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$Domains
    )

    if ($null -eq $Domains) {
        $Domains = Get-Target
    }

    $ForestDnsAdminsMembership = @()

    foreach ($domain in $Domains) {
        $domainDnsAdminsMembership = Get-ADGroupMember 'DnsAdmins' -Recursive -Server $domain
        # TODO Capture nested members with non-standard PGID
        foreach ($member in $domainDnsAdminsMembership) {
            $principal = [PSCustomObject]@{
                'Group Domain' = $domain
                'Member Name'  = $member.Name
                'Member Distinguished Name' = $member.distinguishedName
            }
            if ($ForestDnsAdminsMembership.distinguishedName -notcontains $member.distinguishedName) {
                $ForestDnsAdminsMembership += $principal
            }
        }
    }

    $ForestDnsAdminsMembership
}