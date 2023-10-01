function Test-SecurityDescriptorACE {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$SecurityDescriptors,
        [Parameter()]
        [array]$DynamicUpdateServiceAccounts,
        [Parameter()]
        [array]$Domains
    )

    $FailedSecurityDescriptorACE = @()
    $SafeSIDs = 'S-1-5-9|S-1-5-10|S-1-5-18|S-1-5-32-544'
    $RootDomain = (Get-ADForest $Domains[0]).RootDomain
    $EnterpriseAdminsSID = "$((Get-ADDomain $rootDomain).domainSID.Value)-519"
    $SafeSIDs += "|$EnterpriseAdminsSID"
    # Need to loop through domains
    $KeyAdminsSID = "$((Get-ADDomain $rootDomain).domainSID.Value)-526"
    $EnterpriseKeyAdminsSID = "$((Get-ADDomain $rootDomain).domainSID.Value)-527"
    $SafeGroupSIDs = @()
    foreach ($domain in $Domains) {
        $DomainSID = (Get-ADDomain $domain).DomainSID.Value
        $SafeGroupRIDs = @('-512')
        foreach ($rid in $SafeGroupRIDs ) {
            $SafeGroupSID = $DomainSID + $rid
            $SafeSIDs += "|$SafeGroupSID"
        }
    }
    # $DomainAdminsSIDs = foreach ($domain in $Domains) {
    #     "$((Get-ADDomain $domain).domainSID.Value)-512"
    # }
    # foreach ($sid in $DomainAdminsSIDs) {
    #     $SafeSIDs += "|$sid"
    # }
    foreach ($domain in $Domains) {
        $DomainSID = (Get-ADDomain $domain).DomainSID.Value
        $SafeGroupRIDs = @('-516')
        foreach ($rid in $SafeGroupRIDs ) {
            $DomainControllersSID = $DomainSID + $rid
            $SafeSIDs += "|$DomainControllersSID"
            $members = @()
            $members += (Get-ADGroupMember $DomainControllersSID -Server $domain -Recursive).SID.Value
            foreach ($member in $members) {
                $SafeSIDs += "|$member"
            }
        }
    }
    $DangerousRights = 'GenericAll|WriteDacl|WriteOwner|WriteProperty'

    foreach ($dynamicupdateserviceaccount in $DynamicUpdateServiceAccounts) {
        if ( ($dynamicupdateserviceaccount.'Service Account Name' -ne 'Not Configured') -and
            ($dynamicupdateserviceaccount.'Service Account Domain' -ne 'N/A') ) {
                $identityreference = "$($dynamicupdateserviceaccount.'Service Account Domain')\$($dynamicupdateserviceaccount.'Service Account Name')"
                $dynamicupdateserviceaccountSID = ConvertFrom-IdentityReference -Object $identityreference
                $SafeSIDs += "|$dynamicupdateserviceAccountSID"
        }
    }

    foreach ($securitydescriptor in $SecurityDescriptors) {
        foreach ($ace in $securitydescriptor.Access) {
            $aceName = $securitydescriptor.Owner.split('\')[1]
            if ($aceName.EndsWith('$')) {
                $aceName = $aceName.TrimEnd('$')
            }
            $aceSID = ConvertFrom-IdentityReference -Object $ace.IdentityReference 
            if ( ($aceSID -notmatch $SafeSIDs) -and ($ace.ActiveDirectoryRights -match $DangerousRights) -and 
                ($securitydescriptor.DistinguishedName -notmatch $aceName) -and
                ( ($aceSID -notmatch "$EnterpriseKeyAdminsSID|$KeyAdminsSID") -and ($ace.'Object Type' -ne '5b47d60f-6090-40b2-9f37-2a4de88f3063') ) ) {
                $AddToList = [PSCustomObject]@{
                    Name                      = $securitydescriptor.Name
                    'Identity Reference'      = $ace.IdentityReference
                    'Active Directory Rights' = $ace.ActiveDirectoryRights
                    'Object Type'             = $ace.ObjectType
                    'Inherited Object Type'   = $ace.InheritedObjectType
                }
                $FailedSecurityDescriptorACE += $AddToList
            }
        }
    }

    $FailedSecurityDescriptorACE
}