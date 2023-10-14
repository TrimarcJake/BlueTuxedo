function Test-BTDynamicUpdateServiceAccount {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$DynamicUpdateServiceAccounts
    )

    if ($null -eq $DynamicUpdateServiceAccounts) {
        $DynamicUpdateServiceAccounts = Get-BTDynamicUpdateServiceAccount
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