function Test-WildcardRecord {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$WildcardRecords
    )

    if ($WildcardRecords -eq 1) {
        $correctType = 'A'
    } else {
        $correctType = 'Txt'
    }
    $FailedWildcardRecord = @()
    foreach ($wildcardrecord in $WildcardRecords) {
        if ($wildcardrecord.'Wildcard Type' -ne $correctType) {
            $AddToList = [PSCustomObject]@{
                'Domain'                = $wildcardrecord.'Domain'
                'Wildcard Exists?'      = $wildcardrecord.'Wildcard Exists?'
                'Current Wildcard Type' = $wildcardrecord.'Wildcard Type'
                'Correct Type'          = $correctType
            }
        }

        $FailedWildcardRecord += $AddToList
    }

    $FailedWildcardRecord
}