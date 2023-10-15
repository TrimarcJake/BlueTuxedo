#requires -Modules ActiveDirectory

$LabName = 'BlueTuxedo'
$SusDNS = '86.75.30.9'

# Get Domains in Forest
$Domains = (Get-ADForest).Domains

# Create Stuff in Each Domain
$i = 0
foreach ($domain in $Domains) {    
    # Get Domain's DN
    $DomainRoot = (Get-ADDomain $domain).distinguishedName

    # Create a New OU For Lab Objects
    New-ADOrganizationalUnit -Name $LabName -Path $DomainRoot -Server $domain -ProtectedFromAccidentalDeletion $False -ErrorAction Ignore

    # Create Computer Object
    New-ADComputer -Name "$LabName-DSPN$i" -SAMAccountName "$LabName-DSPN$i" -Path "OU=$LabName,$DomainRoot" -Server $domain -ErrorAction Ignore

    # Assign Custom SPNs to Computer Object
    setspn -s "$LabName/$LabName-DSPN$i" "$domain\$LabName-DSPN$i"
    setspn -s "$LabName/$LabName-DSPN$i.$domain" "$domain\$LabName-DSPN$i"

    # Create a New User
    New-ADUser -Name "$LabName-DnsA$i" -SamAccountName "$LabName-DnsA$i" -Path "OU=$LabName,$DomainRoot" -Server $domain -ErrorAction Ignore

    # Add New User to DnsAdmins
    Add-ADGroupMember -Identity 'DnsAdmins' -Members "$LabName-DnsA$i" -Server $domain -ErrorAction Ignore
    
    # Check for wildcard and wpad records. If found, delete.
    $Records = '*', 'wpad'
    foreach ($record in $Records) {
        $RRTypes = 'A', 'AAAA', 'TXT'
        foreach ($rrtype in $RRTypes) {
            if (Get-DnsServerResourceRecord -ComputerName $domain -ZoneName $domain -RRType $rrtype -Name $record -ErrorAction Ignore) {
                Start-Sleep -Seconds 5
                Remove-DnsServerResourceRecord -ComputerName $domain -ZoneName $domain -RRType $rrtype -Name $record
            }
        }
    }

    # Get all ADI DNS Server Addresses in Domain
    $IPAddresses = (Resolve-DnsName -Type NS -Name $domain).IP4Address

    $j = 0
    foreach ($ipaddress in $IPAddresses) {
        # Add a Suspicious Forwarder
        [array]$Forwarders = (Get-DnsServerForwarder -ComputerName $ipaddress).IPAddress.IPAddressToString
        if ($Forwarders -notcontains $SusDNS) {
            $Forwarders += $SusDNS
            Start-Sleep -Seconds 5
            Set-DnsServerForwarder -ComputerName $ipaddress -IPAddress $Forwarders
        }
        
        Start-Sleep -Seconds 5
        
        # Replace default GQBL entries with a GUID (can't have a blank GQBL?)
        Set-DnsServerGlobalQueryBlockList -ComputerName $ipaddress -List (New-Guid) -PassThru -Verbose

        Start-Sleep -Seconds 10

        # Add Suspicious non-ADI Zones
        Add-DnsServerConditionalForwarderZone -ComputerName $ipaddress -Name "$LabName$i.conditionalforwarder.$j.nonadi" -MasterServers $SusDNS
        # Add-DnsServerPrimaryZone -ComputerName $domain -Name "$LabName$i.primaryzone.$j.nonadi"
        Add-DnsServerStubZone -ComputerName $domain -Name "$LabName$i.stubzone.$j.nonadi" -MasterServers $SusDNS

        # Add Suspicious Zone Scopes + Policies (non-ADI by default)
        # Add-DnsServerZoneScope -ComputerName $ipaddress -ZoneName "$LabName$i.conditionalforwarder.$j.nonadi" -Name "$LabName$i.conditionalforwarder.$j.nonadi_ZoneScope" -LoadExisting -PassThru 
        Add-DnsServerQueryResolutionPolicy -ComputerName $ipaddress -Name "$LabName$i.conditionalforwarder.$j.nonadi_QueryResolutionPolicy" -Action IGNORE -FQDN "EQ,*.$LabName$i.conditionalforwarder.$j.nonadi"
    
        # Add suspicious Secondary Zone
        # Add-DnsServerSecondaryZone -ComputerName $domain -Name "secondaryzone$i$j.$LabName.adi" -MasterServers $SusDNS

        # Set Socket Pool Size To Default
        $CurrentSettings = Get-DnsServerSetting -ComputerName $ipaddress -All
        $CurrentSettings.SocketPoolSize = 2500
        Set-DnsServerSetting -ComputerName $ipaddress -InputObject $CurrentSettings
        
        Start-Sleep -Seconds 5
        $j++
    }

    # Add Suspicious ADI Zones
    $Scopes = 'Forest', 'Domain', 'Legacy'
    foreach ($scope in $Scopes) {
        Add-DnsServerConditionalForwarderZone -ComputerName $domain -Name "$LabName$i.conditionalforwarder.$scope.adi" -ReplicationScope $scope -MasterServers $SusDNS
        Add-DnsServerPrimaryZone -ComputerName $domain -Name "$LabName$i.primaryzone.$scope.adi" -ReplicationScope $scope
        Add-DnsServerStubZone -ComputerName $domain -Name "$LabName$i.stubzone.$scope.adi" -ReplicationScope $scope -MasterServers $SusDNS
        Add-DnsServerZoneScope -ComputerName $domain -ZoneName $domain -Name "$LabName$i.primaryzone.$scope.adi_ZoneScope"
    }

    Start-Sleep -Seconds 5
    $i++
}