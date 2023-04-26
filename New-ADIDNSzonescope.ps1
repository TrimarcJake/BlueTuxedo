function New-ADIDNSZoneScope
{
  ## NOTE: This needs to be modified to create a SOA record or the record will disappear at replication :P
  
    <#
    .SYNOPSIS
    This function adds a DNS zone scope to an Active Directory-Integrated DNS (ADIDNS) Zone scope container through an encrypted LDAP
    add request.

    Author: Kevin Robertson (@kevin_robertson)  
    License: BSD 3-Clause 

    Modified by: Jim Sykora
    
    .DESCRIPTION
    This function creates an ADIDNS zone scope by connecting to LDAP and adding an object of type dnsZoneScope.

    .PARAMETER Credential
    PSCredential object that will be used to add the ADIDNS object.

    .PARAMETER Data
    For most record types this will be the destination hostname or IP address. For TXT records this can be used
    for data.

    .PARAMETER DistinguishedName
    Distinguished name for the ADIDNS zone. Do not include the node name.

    .PARAMETER DNSRecord
    dnsRecord attribute byte array. If not specified, New-DNSRecordArray will generate the array. See MS-DNSP for
    details on the dnsRecord structure.

    .PARAMETER Domain
    The targeted domain in DNS format. This parameter is mandatory on a non-domain attached system.

    .PARAMETER DomainController
    Domain controller to target. This parameter is mandatory on a non-domain attached system.

    .PARAMETER Forest
    The targeted forest in DNS format. This parameter is mandatory on a non-domain attached system.

    .PARAMETER ZoneScope
    The ADIDNS ZoneScope name.

    .PARAMETER Partition
    Default = DomainDNSZones: (DomainDNSZones,ForestDNSZones,System) The AD partition name where the zone is stored.

    .PARAMETER Port
    SRV record port.

    .PARAMETER Preference
    MX record preference.

    .PARAMETER Priority
    SRV record priority.

    .PARAMETER Tombstone
    Switch: Sets the dnsTombstoned flag to true when the node is created. This places the node in a state that
    allows it to be modified or fully tombstoned by any authenticated user.

    .PARAMETER SOASerialNumber
    The current SOA serial number for the target zone. Note, using this parameter will bypass connecting to a
    DNS server and querying an SOA record.

    .PARAMETER Static
    Switch: Zeros out the timestamp to create a static record instead of a dynamic.

    .PARAMETER TTL
    Default = 600: DNS record TTL.

    .PARAMETER Type
    Default = A: DNS record type. This function supports A, AAAA, CNAME, DNAME, NS, MX, PTR, SRV, and TXT.

    .PARAMETER Weight
    SRV record weight.

    .PARAMETER Zone
    The ADIDNS zone. This parameter is mandatory on a non-domain attached system.

    .EXAMPLE
    Add a dnsZoneScope to an ADIDNS zone.
    New-ADIDNSZoneScope -Zone 'test.local' -ZoneScope 'MaliciousZoneScope'

    .EXAMPLE
    Add a dnsZoneScope to an ADIDNS zone from a non-domain attached system.
    $credential = Get-Credential
    New-ADIDNSZoneScope -Zone 'test.local' -ZoneScope 'MaliciousZoneScope' -DomainController dc1.test.local -Domain test.local -Credential $credential

    .LINK
    https://github.com/Kevin-Robertson/Powermad
    #>

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)][String]$Data,
        [parameter(Mandatory=$false)][String]$DistinguishedName,
        [parameter(Mandatory=$false)][String]$Domain,
        [parameter(Mandatory=$false)][String]$DomainController,
        [parameter(Mandatory=$false)][String]$Forest,
        [parameter(Mandatory=$true)][String]$ZoneScope,
        [parameter(Mandatory=$false)][ValidateSet("DomainDNSZones","ForestDNSZones","System")][String]$Partition = "DomainDNSZones",
        [parameter(Mandatory=$false)][ValidateSet("A","AAAA","CNAME","DNAME","MX","NS","PTR","SRV","TXT")][String]$Type = "A",
        [parameter(Mandatory=$true)][String]$Zone,
        [parameter(Mandatory=$false)][Int]$Port,
        [parameter(Mandatory=$false)][Int]$TTL = 600,
        [parameter(Mandatory=$false)][Int32]$SOASerialNumber,
        [parameter(Mandatory=$false)][Switch]$Static,
        [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if($invalid_parameter)
    {
        Write-Output "[-] $($invalid_parameter) is not a valid parameter"
        throw
    }

    $null = [System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.Protocols")

    if(!$DomainController -or !$Domain -or !$Zone -or !$Forest)
    {

        try
        {
            $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
            throw
        }

    }

    if(!$DomainController)
    {
        $DomainController = $current_domain.PdcRoleOwner.Name
        Write-Verbose "[+] Domain Controller = $DomainController"
    }

    if(!$Domain)
    {
        $Domain = $current_domain.Name
        Write-Verbose "[+] Domain = $Domain"
    }

    if(!$Forest)
    {
        $Forest = $current_domain.Forest
        Write-Verbose "[+] Forest = $Forest"
    }

    if(!$Zone)
    {
        $Zone = $current_domain.Name
        Write-Verbose "[+] ADIDNS Zone = $Zone"
    }

    if(!$DistinguishedName)
    {
        
        if($Partition -eq 'System')
        {
            $distinguished_name = "CN=$ZoneScope,CN=ZoneScopeContainer,DC=$Zone,CN=MicrosoftDNS,CN=$Partition"
        }
        else
        {
            $distinguished_name = "CN=$ZoneScope,CN=ZoneScopeContainer,DC=$Zone,CN=MicrosoftDNS,DC=$Partition"
        }

        $DC_array = $Domain.Split(".")

        ForEach($DC in $DC_array)
        {
            $distinguished_name += ",DC=$DC"
        }

        Write-Verbose "[+] Distinguished Name = $distinguished_name"
    }
    else 
    {
        $distinguished_name = "CN=$ZoneScope,CN=ZoneScopeContainer," + $DistinguishedName
    }


    $identifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($DomainController,389)

    if($Credential)
    {
        $connection = New-Object System.DirectoryServices.Protocols.LdapConnection($identifier,$Credential.GetNetworkCredential())
    }
    else
    {
        $connection = New-Object System.DirectoryServices.Protocols.LdapConnection($identifier)
    }

    $object_category = "CN=Dns-Zone-Scope,CN=Schema,CN=Configuration"
    $forest_array = $Forest.Split(".")

    ForEach($DC in $forest_array)
    {
        $object_category += ",DC=$DC"
    }
    
    try
    {
        $connection.SessionOptions.Sealing = $true
        $connection.SessionOptions.Signing = $true
        $connection.Bind()
        $request = New-Object -TypeName System.DirectoryServices.Protocols.AddRequest
        $request.DistinguishedName = $distinguished_name
        $request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass",@("top","dnsZoneScope"))) > $null
        $request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectCategory",$object_category)) > $null
        $request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "dc",$ZoneScope)) > $null

        $connection.SendRequest($request) > $null
        Write-Output "[+] ADIDNS ZoneScope $ZoneScope added"
    }
    catch
    {
        Write-Output "[-] $($_.Exception.Message)"
    }

}