function Test-BTGlobalQueryBlockList {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$GlobalQueryBlockLists
    )

    if ($null -eq $GlobalQueryBlockLists) {
        $GlobalQueryBlockLists = Get-BTGlobalQueryBlockList
    }

    $FailedGlobalQueryBlockList = @()
    foreach ($globalqueryblocklist in $GlobalQueryBlockLists) {
        $wpadExists = $true
        $isatapExists = $true
        if ($globalqueryblocklist.GQBL -notcontains 'wpad') {
            $wpadExists = $false
        }
        if ($globalqueryblocklist.GQBL -notcontains 'isatap') {
            $isatapExists = $false
        }

        if ( ($globalqueryblocklist.'Enabled?' -eq $false) -or ($wpadExists = $false) -or ($isatapExists -eq $false) ) {
            $AddToList = [PSCustomObject]@{
                'Server Name'   = $globalqueryblocklist.'Server Name'
                'Server IP'     = $globalqueryblocklist.'Server IP'
                'Enabled?'      = $globalqueryblocklist.'Enabled?'
                'WPAD Exists'   = $wpadExists
                'ISATAP Exists' = $isatapExists
            }
    }

        $FailedGlobalQueryBlockList += $AddToList
    }

    $FailedGlobalQueryBlockList
}