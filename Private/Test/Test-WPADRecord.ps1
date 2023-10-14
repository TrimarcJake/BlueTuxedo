function Test-WPADRecord {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$WPADRecords
    )

    if ($null -eq $WPADRecords) {
        $WPADRecords = Get-WPADRecord
    }

    if ($WPADRecords -eq 1) {
        $correctType = 'A'
    } else {
        $correctType = 'Txt'
    }
    $FailedWPADRecord = @()
    foreach ($wpadrecord in $WPADRecords) {
        if ($wpadrecord.'WPAD Type' -ne $correctType) {
            $AddToList = [PSCustomObject]@{
                'Domain'                = $wpadrecord.'Domain'
                'WPAD Exists?'      = $wpadrecord.'WPAD Exists?'
                'Current WPAD Type' = $wpadrecord.'WPAD Type'
                'Correct Type'          = $correctType
            }
        }

        $FailedWPADRecord += $AddToList
    }

    $FailedWPADRecord
}