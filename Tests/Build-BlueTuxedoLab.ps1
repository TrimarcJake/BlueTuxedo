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
    New-ADOrganizationalUnit -Name 'ADIDNSLab' -Path $DomainRoot -Server $domain

    # Create Computer Object
    New-ADComputer -Name "DSPN$i" -SAMAccountName "DSPN$i" -Path "OU=ADIDNSLab,$DomainRoot" -Server $domain

    $i++
}

