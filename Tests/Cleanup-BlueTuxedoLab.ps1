$LabName = 'BlueTuxedo'
$SusDNS = '86.75.30.9'

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
    Remove-ADObject -Identity "OU=$LabName,$DomainRoot" -Recursive -Server $domain -Confirm:$false -ErrorAction Ignore

    # Get All ADI DNS Server Addresses in Domain
    $IPAddresses = (Resolve-DnsName -Type NS -Name $domain).IP4Address

    # Restore default GQBL entries
    foreach ($ipaddress in $IPAddresses) {
        Set-DnsServerGlobalQueryBlockList -ComputerName $ipaddress -List 'isatap','wpad'
    }

    # Get All ADI DNS Server Addresses in Domain
    $IPAddresses = (Resolve-DnsName -Type NS -Name $domain).IP4Address

    foreach ($ipaddress in $IPAddresses) {
         # Remove Suspicious Forwarders
        [array]$Forwarders = (Get-DnsServerForwarder -ComputerName $ipaddress).IPAddress.IPAddressToString
        if ($Forwarders -contains $SusDNS) {
            Remove-DnsServerForwarder -COmputerName $ipaddress -IPAddress $SusDNS -Force 
        }
        
        # Remove Suspicious Zones
        Get-DnsServerZone -ComputerName $ipaddress | Where-Object ZoneName -match "^$LabName[0-9]" | Remove-DnsServerZone -ComputerName $ipaddress -Force

        # Remove Suspicious Zone Scopes
        Get-DnsServerZoneScope -ComputerName $ipaddress -ZoneName $domain | Where-Object ZoneScope -match "^$LabName[0-9]" | Remove-DnsServerZoneScope -ComputerName $ipaddress -Force

        # Remove Query Resolution Policies
        Get-DnsServerQueryResolutionPolicy -ComputerName $ipaddress | Where-Object Name -match "^$LabName[0-9]" | Remove-DnsServerQueryResolutionPolicy -ComputerName $ipaddress -Force
    }

    # Emtpy AD Recyle Bin    
    Get-ADObject -Filter { isDeleted -eq $True } -IncludeDeletedObjects | Where-Object sAMAccountName -match "^$LabName[0-9]" | Remove-ADObject
}