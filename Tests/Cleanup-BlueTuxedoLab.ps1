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
        Remove-ADGroupMember -Identity 'DnsAdmins' -Members $_ -Confirm:$false    
    }

    # Remove BlueTuxedo OU and all Lab Objects
    Remove-ADObject -Identity "OU=BlueTuxedo,$DomainRoot" -Recursive -Server $domain -Confirm:$false

    # Get All ADI DNS Server Addresses in Domain
    $IPAddresses = (Resolve-DnsName -Type NS -Name $domain).IP4Address

    # Restore default GQBL entries
    foreach ($ipaddress in $IPAddresses) {
        Set-DnsServerGlobalQueryBlockList -ComputerName $ipaddress -List 'isatap','wpad'
    }

    # Remove suspicious Forwarders

    # Remove suspicious Conditional Forwarder Zones

}