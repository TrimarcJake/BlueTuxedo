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

    # Add ADI Bad Conditional Forwarder (currently not working)
    # Add-DnsServerConditionalForwarderZone -Name 'bluetuxedo.adi' -ReplicationScope 'Forest' -MasterServers '0.0.0.0'

    # Get All ADI DNS Server Addresses in Domain
    $IPAddresses = (Resolve-DnsName -Type NS -Name $domain).IP4Address

    $j = 0
    foreach ($ipaddress in $IPAddresses) {
        # Replace default GQBL entries with a GUID (can't have a blank GQBL?)
        Set-DnsServerGlobalQueryBlockList -ComputerName $ipaddress -List (New-Guid)

        # Add non-ADI Bad Conditional Forwarder (currently not working)
        # Add-DnsServerConditionalForwarderZone -Name 'bluetuxedo.nonadi' -ComputerName $ipaddress -MasterServers '0.0.0.0'

        # Set Socket Pool Size To Default
        $CurrentSettings = Get-DnsServerSetting -ComputerName $ipaddress -All
        $CurrentSettings.SocketPoolSize = 2500
        Set-DnsServerSetting -ComputerName $ipaddress -InputObject $CurrentSettings

        $j++
    }

    $i++
}