#Assign some variables
$StdOwnersFS = {($_.ntSecurityDescriptor.Owner -ne "NT AUTHORITY\SYSTEM") -and ($_.ntSecurityDescriptor.Owner -notlike "*\Administrator") -and ($_.ntSecurityDescriptor.Owner -notlike "*\Domain Admins") -and ($_.ntSecurityDescriptor.Owner -notlike "*\*$")}
$AuthUsersFS = {($_.ntSecurityDescriptor.Access.IdentityReference -eq "NT AUTHORITY\Authenticated Users") -and! ($_.ntSecurityDescriptor.Access.ActiveDirectoryRights -eq "CreateChild")} # -not ($_.nt.SecurityDescriptor.Access.IsInherited -eq "False")}
$StdACEsFS = {($_.ntSecurityDescriptor.Access.IdentityReference -ne "BUILTIN\Administrators") -and ($_.ntSecurityDescriptor.Access.IdentityReference -ne "S-1-5-32-554") -and ($_.ntSecurityDescriptor.Access.IdentityReference -ne "NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS") -and ($_.ntSecurityDescriptor.Access.IdentityReference -ne "NT AUTHORITY\SYSTEM") -and ($_.ntSecurityDescriptor.Access.IdentityReference -ne "NT AUTHORITY\SELF") -and ($_.ntSecurityDescriptor.Access.IdentityReference -notlike "*\Domain Admins") -and ($_.ntSecurityDescriptor.Access.IdentityReference -notlike "*\Enterprise Admins") -and ($_.ntSecurityDescriptor.Access.IdentityReference -notlike "*\Domain Admins")}

# Discover DNS Objects: dnsNodes dnsZone, dnsZoneScopeContainer, dnsZoneScope
try
{
    Import-Module ActiveDirectory
    # Might be better to pull the partitions from CN=Partitions,CN=Configuration,DC=marvel,DC=local using the .nCname attribute to get all forest partitions?
    $SearchPaths = (Get-ADRootDSE).namingContexts
    #dnsNodes
    $dnsNodes = $SearchPaths | ForEach-Object {Get-ADObject -Filter 'objectClass -eq "dnsNode"' -SearchBase $_ -Properties *}  
    Write-Host 'Discovered dnsNodes: '$dnsNodes.Count
    #dnsZones, dnsZoneScopes, and dnsZoneScopeContainers
    $dnsZones = $SearchPaths | ForEach-Object {Get-ADObject -Filter 'objectClass -eq "dnsZone" -or objectClass -eq "dnsZoneScopeContainer" -or objectClass -eq "dnsZoneScope"' -SearchBase $_ -Properties *}  
    Write-Host 'Discovered dnsZones (and subordinate zones objects): '$dnsZones.Count
    #dnsHeadObject
    $dnsHead = 'CN=MicrosoftDNS,CN=System,'+ (Get-ADRootDSE).defaultNamingContext
    Write-Host 'DNS Head Object: ' $dnsHead
    #All DNS Objects - This is kinda redundant but might be interesting :P  After exploring a bit, just split everything up into dnsNodes and dnsZone(ish) stuff.
    $allDNS = $SearchPaths | ForEach-Object {Get-ADObject -Filter 'objectClass -eq "dnsNode" -or objectClass -eq "dnsZone" -or objectClass -eq "dnsZoneScopeContainer" -or objectClass -eq "dnsZoneScope"' -SearchBase $_ -Properties *} 
    Write-Host 'All DNS Objects: '$allDNS.Count
} 
catch
{
    Write-Error $_
}
# Get ACLs on these objects and then filter them
try
{
<#  #Let's start with All DNS Objects, for fun: (It wasn't that fun because most of these generic queries ended up leaving out dnsNodes)
    #Nonstandard Ownership of DNS Objects
    $NonStandardOwners = $allDNS | Where-Object {($_.ntSecurityDescriptor.Owner -ne "NT AUTHORITY\SYSTEM") -and ($_.ntSecurityDescriptor.Owner -notlike "*\Administrator") -and ($_.ntSecurityDescriptor.Owner -notlike "*\Domain Admins") -and ($_.ntSecurityDescriptor.Owner -notlike "*\*$")}
    Write-Host 'Nonnstandard Owners: '$NonStandardOwners.Count 'out of' $allDNS.Count 'DNS objects'
    #Objects with Authenticated Users ACE
    $AuthUsersACE = $allDNS | Where-Object {($_.ntSecurityDescriptor.Access.IdentityReference -eq "NT AUTHORITY\Authenticated Users") -and ($_.nt.SecurityDescriptor.Access.IsInherited -eq "False")}
    #AuthUsersACE without CreateChild ADRights as I couldn't get it to filter correctly above :P  also, this seems to be working only for Zones and isn't including Nodes
    $NonStandardAuthUsersACE = $AuthUsersACE | Where-Object {($_.ntSecurityDescriptor.Access.ActiveDirectoryRights -ne "CreateChild")}
#>
    #Nonstandard Ownership of DNS Zone Objects
    $NonStandardZoneOwners = $dnsZones | Where-Object -FilterScript $StdOwnersFS 
    Write-Host 'Nonnstandard Zone Owners: '$NonStandardZoneOwners.Count 'out of' $dnsZones.Count 'DNS Zone objects'
    #Objects with Authenticated Users ACE (not working right. The filter is only flagging on AuthUsers and not the other validation)
    $AuthUsersZoneACE = $dnsZones | Where-Object -FilterScript $AuthUsersFS 
    #AuthUsersAC (not working right)
    $NonStandardAuthUsersZoneACE = $AuthUsersZoneACE | Where-Object -FilterScript $StdACEsFS #{($_.ntSecurityDescriptor.Access.ActiveDirectoryRights -ne "CreateChild")}
    Write-Host 'Zones with AuthUser permissions: ' $AuthUsersZoneAce.Count

    #Nonstandard Ownership of dnsNodes
    $NonStandardNodeOwners = $dnsNodes | Where-Object -FilterScript $StdOwnersFS
    Write-Host 'Nonnstandard Node Owners: '$NonStandardNodeOwners.Count 'out of' $dnsNodes.Count 'dnsNode objects'
    #Objects with Authenticated Users ACE (not working right)
    $AuthUsersNodeACE = $dnsNodes | Where-Object -FilterScript $AuthUsersFS 
    #AuthUsersACE without CreateChild ADRights (not working right)
    $NonStandardAuthUsersNodeACE = $AuthUsersNodeACE | Where-Object -FilterScript $StdACEsFS #{($_.ntSecurityDescriptor.Access.ActiveDirectoryRights -ne "CreateChild")}
    Write-Host 'dnsNodes with AuthUser permissions: ' $AuthUsersNodeAce.Count

    <#dnsNodes with Authenticated Users ACE - Trying stuff because the previous isn't working the way I wanted
    $AuthUsersNodes = $dnsNodes | Where-Object {($_.ntSecurityDescriptor.Access.IdentityReference -eq "NT AUTHORITY\Authenticated Users")}
     -and ($_.nt.SecurityDescriptor.Access.IsInherited -eq "False")}
     #>
}
catch
{
    Write-Error $_
}