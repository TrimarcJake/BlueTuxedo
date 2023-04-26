IF (!$Domain)
 { $Domain = (Get-ADDomain).DNSRoot } 

Import-Module ActiveDirectory
##Import-Module GroupPolicy

## Get AD Forest & Domain Info
$ADForestInfo = Get-ADForest
$ForestDNSName = $ADForestInfo.Name
$ADDomainInfo = Get-ADDomain $Domain
$ADDomainNetBIOSName = $ADDomainInfo.NetBIOSName
$ADDomainName = $ADDomainInfo.DNSRoot
$DomainDN = $ADDomainInfo.DistinguishedName
$DomainDC = $ADDomainInfo.PDCEmulator 

## Identify Accounts with Kerberos Delegation
$KerberosDelegationArray = @()
[array]$KerberosDelegationObjects =  Get-ADObject -filter { ((UserAccountControl -BAND 0x0080000) -OR (UserAccountControl -BAND 0x1000000) -OR (msDS-AllowedToDelegateTo -like '*') -OR (msDS-AllowedToActOnBehalfOfOtherIdentity -like '*')) -AND (PrimaryGroupID -ne '516') -AND (PrimaryGroupID -ne '521') } -Server $DomainDC -prop Name,ObjectClass,PrimaryGroupID,UserAccountControl,ServicePrincipalName,msDS-AllowedToDelegateTo,msDS-AllowedToActOnBehalfOfOtherIdentity -SearchBase $DomainDN 

ForEach ($KerberosDelegationObjectItem in $KerberosDelegationObjects)
 {
    IF ($KerberosDelegationObjectItem.UserAccountControl -BAND 0x0080000)
     { $KerberosDelegationServices = 'All Services' ; $KerberosType = 'Unconstrained' }
    ELSE 
     { $KerberosDelegationServices = 'Specific Services' ; $KerberosType = 'Constrained' } 

    IF ($KerberosDelegationObjectItem.UserAccountControl -BAND 0x1000000)
     { $KerberosDelegationAllowedProtocols = 'Any (Protocol Transition)' ; $KerberosType = 'Constrained with Protocol Transition' }
    ELSE
     { $KerberosDelegationAllowedProtocols = 'Kerberos' }

    IF ($KerberosDelegationObjectItem.'msDS-AllowedToActOnBehalfOfOtherIdentity')
     { $KerberosType = 'Resource-Based Constrained Delegation'  } 

    $KerberosDelegationObjectItem | Add-Member -MemberType NoteProperty -Name Domain -Value $Domain -Force
    $KerberosDelegationObjectItem | Add-Member -MemberType NoteProperty -Name KerberosDelegationServices -Value $KerberosDelegationServices -Force
    $KerberosDelegationObjectItem | Add-Member -MemberType NoteProperty -Name DelegationType -Value $KerberosType -Force
    $KerberosDelegationObjectItem | Add-Member -MemberType NoteProperty -Name KerberosDelegationAllowedProtocols -Value $KerberosDelegationAllowedProtocols -Force

    [array]$KerberosDelegationArray += $KerberosDelegationObjectItem
 }

<#
Write-Host ""
Write-Host "$Domain Domain Accounts with Kerberos Delegation:" -Fore Cyan
$KerberosDelegationArray | Sort DelegationType | Select DistinguishedName,DelegationType,Name,ServicePrincipalName | Format-Table -AutoSize
Write-Host ""
#>

ForEach ($SPN in $KerberosDelegationArray.ServicePrincipalName)
{
   # Write-Host $SPN
   # Write-Host ""
    $ht = [ordered]@{
        'ServicePrincipalName' = $SPN
        'SPNServiceClass' = $SPN.Split('/')[0]
        'SPNHost' = $SPN.Split('/')[1]
        #'SPNPort' = $SPNHost.Split(':')[1]
        #'SPNServiceName' = $SPN.Split
        'Domain' = $KerberosDelegationArray.Where({$_.ServicePrincipalName -eq $SPN}) | Select-Object -ExpandProperty Domain
        'KerberosDelegationServices' = $KerberosDelegationArray.Where({$_.ServicePrincipalName -eq $SPN}) | Select-Object -ExpandProperty KerberosDelegationServices
        'DelegationType' = $KerberosDelegationArray.Where({$_.ServicePrincipalName -eq $SPN}) | Select-Object -ExpandProperty DelegationType
        'KerberosDelegationAllowedProtocols' = $KerberosDelegationArray.Where({$_.ServicePrincipalName -eq $SPN}) | Select-Object -ExpandProperty KerberosDelegationAllowedProtocols
        'DistinguishedName' = $KerberosDelegationArray.Where({$_.ServicePrincipalName -eq $SPN}) | Select-Object -ExpandProperty DistinguishedName
        'msDS-AllowedToActOnBehalfOfOtherIdentity' = $KerberosDelegationArray.Where({$_.ServicePrincipalName -eq $SPN}) | Select-Object -ExpandProperty msDS-AllowedToActOnBehalfOfOtherIdentity 
        'msDS-AllowedToDelegateTo' = $KerberosDelegationArray.Where({$_.ServicePrincipalName -eq $SPN}) | Select-Object -ExpandProperty msDS-AllowedToDelegateTo 
        'Name' = $KerberosDelegationArray.Where({$_.ServicePrincipalName -eq $SPN}) | Select-Object -ExpandProperty Name
        'ObjectClass' = $KerberosDelegationArray.Where({$_.ServicePrincipalName -eq $SPN}) | Select-Object -ExpandProperty ObjectClass
        'UserAccountControl' = $KerberosDelegationArray.Where({$_.ServicePrincipalName -eq $SPN}) | Select-Object -ExpandProperty UserAccountControl
        }
   # $KerberosDelegationArray.Where({$_.ServicePrincipalName -eq $SPN}) | Select-Object Domain


    [array]$SPNArray += New-Object -TypeName psobject -Property $ht
}