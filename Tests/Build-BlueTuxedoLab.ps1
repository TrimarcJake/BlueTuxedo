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
    New-ADOrganizationalUnit -Name 'BlueTuxedo' -Path $DomainRoot -Server $domain -ProtectedFromAccidentalDeletion $False

    # Create Computer Object
    New-ADComputer -Name "BlueTuxedoDSPN$i" -SAMAccountName "BlueTuxedoDSPN$i" -Path "OU=BlueTuxedo,$DomainRoot" -Server $domain

    # Assign Custom SPNs to Computer Object
    setspn -s "BlueTuxedo/BlueTuxedoDSPN$i" "$domain\BlueTuxedoDSPN$i"
    setspn -s "BlueTuxedo/BlueTuxedoDSPN$i.$domain" "$domain\BlueTuxedoDSPN$i"

    # Create New User
    New-ADUser -Name "BlueTuxedoDnsAdmins$i" -SamAccountName "BlueTuxedoDnsAdmins$i" -Path "OU=BlueTuxedo,$DomainRoot" -Server $domain

    # Add New User to DnsAdmins
    Add-ADGroupMember -Identity 'DnsAdmins' -Members "BlueTuxedoDnsAdmins$i" -Server $domain
    
    $i++
}