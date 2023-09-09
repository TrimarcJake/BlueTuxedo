#requires -Modules ActiveDirectory

# Get Root
$RootDSE = (Get-ADRootDSE).defaultNamingContext

# Get Domains in Forest
$Domains = (Get-ADForest).Domains

# Create Stuff in Each Domain
$i = 0
foreach($domain in $Domains) {    
    # Get Domain's DN
    $DomainRoot = (Get-ADDomain $domain).distinguishedName

    # Create New OU For Lab Objects
    New-ADOrganizationalUnit -Name 'BlueTuxedo' -Path $DomainRoot -Server $domain -ProtectedFromAccidentalDeletion $False -ErrorAction Ignore

    # Create Computer Object
    New-ADComputer -Name "BlueTuxedoDSPN$i" -SAMAccountName "BlueTuxedoDSPN$i" -Path "OU=BlueTuxedo,$DomainRoot" -Server $domain -ErrorAction Ignore

    # Assign Custom SPNs to Computer Object
    setspn -s "BlueTuxedo/BlueTuxedoDSPN$i" "$domain\BlueTuxedoDSPN$i"
    setspn -s "BlueTuxedo/BlueTuxedoDSPN$i.$domain" "$domain\BlueTuxedoDSPN$i"

    # Create New User
    New-ADUser -Name "BlueTuxedoDnsAdmins$i" -SamAccountName "BlueTuxedoDnsAdmins$i" -Path "OU=BlueTuxedo,$DomainRoot" -Server $domain -ErrorAction Ignore

    # Add New User to DnsAdmins
    Add-ADGroupMember -Identity 'DnsAdmins' -Members "BlueTuxedoDnsAdmins$i" -Server $domain -ErrorAction Ignore
    
    # Check for wildcard and wpad records. If found, delete.
    $Records = '*','wpad'
    foreach($record in $Records) {
        $RRTypes = 'A','AAAA','TXT'
        foreach($rrtype in $RRTypes) {
            if (Get-DnsServerResourceRecord -ComputerName $domain -ZoneName $domain -RRType $rrtype -Name $record -ErrorAction Ignore) {
                Remove-DnsServerResourceRecord -ComputerName $domain -ZoneName $domain -RRType $rrtype -Name $record
            }
        }
    }

    # Get All ADI DNS Server Addresses in Domain
    $IPAddresses = (Resolve-DnsName -Type NS -Name $domain).IP4Address

    # Replace default GQBL entries with a GUID (can't have a blank GQBL?)
    foreach ($ipaddress in $IPAddresses) {
        Set-DnsServerGlobalQueryBlockList -ComputerName $ipaddress -List (New-Guid)
    }



    $i++
}