function Test-GlobalQueryBlockList {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$GlobalQueryBlockLists
    )

    if ($null -eq $GlobalQueryBlockLists) {
        $GlobalQueryBlockLists = Get-GlobalQueryBlockList
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

        $AddToList = [PSCustomObject]@{
            'Server Name'    = $globalqueryblocklist.'Server Name'
            'Server IP'      = $globalqueryblocklist.'Server IP'
            'WPAD Exists'   = $wpadExists
            'ISATAP Exists' = $isatapExists
        }

        $FailedGlobalQueryBlockList += $AddToList
    }

    $FailedGlobalQueryBlockList
}