function Test-BTSecurityDescriptorOwner {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$SecurityDescriptors,
        [Parameter()]
        [array]$DynamicUpdateServiceAccounts,
        [Parameter()]
        [array]$Domains
    )

    if ($null -eq $SecurityDescriptors) {
        $SecurityDescriptors = Get-BTSecurityDescriptor
    }

    if ($null -eq $DynamicUpdateServiceAccounts) {
        $DynamicUpdateServiceAccounts = Get-BTDynamicUpdateServiceAccount
    }

    if ($null -eq $Domains) {
        $Domains = Get-BTTarget
    }

    $FailedSecurityDescriptorOwner = @()
    $SafeSIDs = 'S-1-5-18'
    $RootDomain = (Get-ADForest $Domains[0]).RootDomain
    $EnterpriseAdminsSID = "$((Get-ADDomain $rootDomain).domainSID.Value)-519"
    $SafeSIDs += "|$EnterpriseAdminsSID"
    $DomainAdminsSIDs = foreach ($domain in $Domains) {
        "$((Get-ADDomain $domain).domainSID.Value)-512"
    }
    foreach ($sid in $DomainAdminsSIDs) {
        $SafeSIDs += "|$sid"
    }

    foreach ($dynamicupdateserviceaccount in $DynamicUpdateServiceAccounts) {
        if ( ($dynamicupdateserviceaccount.'Service Account Name' -ne 'Not Configured') -and
            ($dynamicupdateserviceaccount.'Service Account Domain' -ne 'N/A') ) {
                $identityreference = "$($dynamicupdateserviceaccount.'Service Account Domain')\$($dynamicupdateserviceaccount.'Service Account Name')"
                $dynamicupdateserviceaccountSID = ConvertFrom-IdentityReference -Object $identityreference
                $SafeSIDs += "|$dynamicupdateserviceAccountSID"
        }
    }

    foreach ($securitydescriptor in $SecurityDescriptors) {
        $owner = $securitydescriptor.Owner
        $ownerName = $securitydescriptor.Owner.split('\')[1]
        if ($ownerName.EndsWith('$')) {
            $ownerName = $ownerName.TrimEnd('$')
        }
        $ownerSID = ConvertFrom-IdentityReference -Object $owner
        if ( ($ownerSID -notmatch $SafeSIDs) -and ($securitydescriptor.DistinguishedName -notmatch $ownerName) ) {
            $FailedSecurityDescriptorOwner += $securitydescriptor | Select-Object Name, Owner, DistinguishedName
        }
    }

    $FailedSecurityDescriptorOwner
}