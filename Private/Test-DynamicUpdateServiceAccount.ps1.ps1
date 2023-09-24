function Test-DynamicUpdateServiceAccount {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$DynamicUpdateServiceAccounts
    )

    $FailedDynamicUpdateServiceAccount = @()
    foreach ($dynamicupdateserviceaccount in $DynamicUpdateServiceAccounts) {
        if ( ($dynamicupdateserviceaccount.'Service Account Name' -eq 'Not Configured') -and 
            ($dynamicupdateserviceaccount.'Service Account Domain' -eq 'N/A') ) {
            $FailedDynamicUpdateServiceAccount += $dynamicupdateserviceaccount
        }
    }

    $FailedDynamicUpdateServiceAccount
}