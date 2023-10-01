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
    $DomainAdminsSIDs = foreach ($domain in $Domains) {
        "$((Get-ADDomain $domain).domainSID.Value)-512"
    }
    foreach ($sid in $DomainAdminsSIDs) {
        $SafeSIDs += "|$sid"
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
            $aceSID = ConvertFrom-IdentityReference -Object $ace.IdentityReference
            if ( ($aceSID -notmatch $SafeSIDs) -and ($ace.ActiveDirectoryRights -match $DangerousRights) ) {
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