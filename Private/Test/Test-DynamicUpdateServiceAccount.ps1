function Test-DynamicUpdateServiceAccount {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$DynamicUpdateServiceAccounts
    )

    if ($null -eq $DynamicUpdateServiceAccounts) {
        $DynamicUpdateServiceAccounts = Get-DynamicUpdateServiceAccount
    }

    $FailedDynamicUpdateServiceAccount = @()
    foreach ($dynamicupdateserviceaccount in $DynamicUpdateServiceAccounts) {
        if ( ($dynamicupdateserviceaccount.'Service Account Name' -eq 'Not Configured') -and 
            ($dynamicupdateserviceaccount.'Service Account Domain' -eq 'N/A') ) {
            $FailedDynamicUpdateServiceAccount += $dynamicupdateserviceaccount
        }
    }

    $FailedDynamicUpdateServiceAccount
}