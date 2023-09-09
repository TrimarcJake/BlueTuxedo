#requires -Modules ActiveDirectory

$LabName = 'BlueTuxedo'
$SusDNS = '86.75.30.9'

# Get Root
$RootDSE = (Get-ADRootDSE).defaultNamingContext

# Get Domains in Forest
$Domains = (Get-ADForest).Domains

# Create Stuff in Each Domain
$i = 0
foreach ($domain in $Domains) {    
    # Get Domain's DN
    $DomainRoot = (Get-ADDomain $domain).distinguishedName

    # Create New OU For Lab Objects
    New-ADOrganizationalUnit -Name $LabName -Path $DomainRoot -Server $domain -ProtectedFromAccidentalDeletion $False -ErrorAction Ignore

    # Create Computer Object
    New-ADComputer -Name "$LabName-DSPN$i" -SAMAccountName "$LabName-DSPN$i" -Path "OU=$LabName,$DomainRoot" -Server $domain -ErrorAction Ignore

    # Assign Custom SPNs to Computer Object
    setspn -s "$LabName/$LabName-DSPN$i" "$domain\$LabName-DSPN$i"
    setspn -s "$LabName/$LabName-DSPN$i.$domain" "$domain\$LabName-DSPN$i"

    # Create New User
    New-ADUser -Name "$LabName-DnsA$i" -SamAccountName "$LabName-DnsA$i" -Path "OU=$LabName,$DomainRoot" -Server $domain -ErrorAction Ignore

    # Add New User to DnsAdmins
    Add-ADGroupMember -Identity 'DnsAdmins' -Members "$LabName-DnsA$i" -Server $domain -ErrorAction Ignore
    
    # Check for wildcard and wpad records. If found, delete.
    $Records = '*', 'wpad'
    foreach ($record in $Records) {
        $RRTypes = 'A', 'AAAA', 'TXT'
        foreach ($rrtype in $RRTypes) {
            if (Get-DnsServerResourceRecord -ComputerName $domain -ZoneName $domain -RRType $rrtype -Name $record -ErrorAction Ignore) {
                Remove-DnsServerResourceRecord -ComputerName $domain -ZoneName $domain -RRType $rrtype -Name $record
            }
        }
    }

    # Get All ADI DNS Server Addresses in Domain
    $IPAddresses = (Resolve-DnsName -Type NS -Name $domain).IP4Address

    $j = 0
    foreach ($ipaddress in $IPAddresses) {
        # Replace default GQBL entries with a GUID (can't have a blank GQBL?)
        Set-DnsServerGlobalQueryBlockList -ComputerName $ipaddress -List (New-Guid)

        # Add a suspicious Forwarder
        [array]$Forwarders = (Get-DnsServerForwarder -ComputerName $ipaddress).IPAddress.IPAddressToString
        if ($Forwarders -notcontains $SusDNS) {
            $Forwarders += $SusDNS
            Set-DnsServerForwarder -ComputerName $ipaddress -IPAddress $Forwarders
        }

        # Add non-ADI Bad Conditional Forwarder
        Add-DnsServerConditionalForwarderZone -Name "$LabName$i.conditionalforwarder.$j.nonadi" -ComputerName $ipaddress -MasterServers $SusDNS
        
        # Add suspicious Secondary Zone
        # Add-DnsServerSecondaryZone -ComputerName $domain -Name "secondaryzone$i$j.$LabName.adi" -MasterServers $SusDNS

        # Set Socket Pool Size To Default
        # $CurrentSettings = Get-DnsServerSetting -ComputerName $ipaddress -All
        # $CurrentSettings.SocketPoolSize = 2500
        # Set-DnsServerSetting -ComputerName $ipaddress -InputObject $CurrentSettings
        
        Start-Sleep -Seconds 5
        $j++
    }

    # Add Suspicious ADI Zones, Forwarder Zones, etc.
    $Scopes = 'Forest', 'Domain', 'Legacy'
    foreach ($scope in $Scopes) {
        Add-DnsServerConditionalForwarderZone -ComputerName $domain -Name "$LabName$i.conditionalforwarder.$scope.adi" -ReplicationScope $scope -MasterServers $SusDNS
        Add-DnsServerPrimaryZone -ComputerName $domain -Name "$LabName$i.primaryzone.$scope.adi" -ReplicationScope $scope
        Add-DnsServerStubZone -ComputerName $domain -Name "$LabName$i.stubzone.$scope.adi" -ReplicationScope $scope -MasterServers $SusDNS
    }

    Start-Sleep -Seconds 5
    $i++
}