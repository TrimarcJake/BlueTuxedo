# Get Root
$RootDSE = (Get-ADRootDSE).defaultNamingContext

# Get Domains in Forest
$Domains = (Get-ADForest).Domains

# Delete Lab OU(s)
foreach ($domain in $Domains) {
    # Get Domain's DN
    $DomainRoot = (Get-ADDomain $domain).distinguishedName

    # Remove BlueTuxedo* Users from DnsAdmins
    Get-ADUser -Filter { Name -like 'BlueTuxedo*' } | ForEach-Object {
        Remove-ADGroupMember -Identity 'DnsAdmins' -Members $_         
    }

    # Remove BlueTuxedo OU and all Lab Objects
    Remove-ADObject -Identity "OU=BlueTuxedo,$DomainRoot" -Recursive -Server $domain
}