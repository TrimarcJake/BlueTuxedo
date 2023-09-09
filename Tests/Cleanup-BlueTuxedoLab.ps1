$LabName = 'BlueTuxedo'
$SusDNS = '86.75.30.9'

# Get Root
$RootDSE = (Get-ADRootDSE).defaultNamingContext

# Get Domains in Forest
$Domains = (Get-ADForest).Domains

# Delete Lab OU(s)
foreach ($domain in $Domains) {
    # Get Domain's DN
    $DomainRoot = (Get-ADDomain $domain).distinguishedName

    # Remove $LabName* Users from DnsAdmins
    Get-ADUser -Filter { Name -like '$LabName*' } | ForEach-Object {
        Remove-ADGroupMember -Identity 'DnsAdmins' -Members $_ -Confirm:$false    
    }

    # Remove $LabName OU and all Lab Objects
    Remove-ADObject -Identity "OU=$LabName,$DomainRoot" -Recursive -Server $domain -Confirm:$false

    # Get All ADI DNS Server Addresses in Domain
    $IPAddresses = (Resolve-DnsName -Type NS -Name $domain).IP4Address

    # Restore default GQBL entries
    foreach ($ipaddress in $IPAddresses) {
        Set-DnsServerGlobalQueryBlockList -ComputerName $ipaddress -List 'isatap','wpad'
    }

    # Remove suspicious Forwarders

    # Remove suspicious Conditional Forwarder Zones

}