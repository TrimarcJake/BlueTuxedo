function Test-ZoneScopeContainer {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$ZoneScopeContainers
    )

    $FailedZoneScopeContainerList = @()

    foreach ($zoneScopeContainer in $ZoneScopeContainers) {
        $isEmpty = $true
        if ( (Get-ADObject -Filter * -SearchBase $zoneScopeContainer.'Zone Scope Container DN' -Server $zoneScopeContainer.Domain).Count -gt 0) {
            break
        } else {
            $AddToList = [PSCustomObject]@{
                'Domain'    = $zoneScopeContainer.Domain
                'Zone Name' = $zoneScopeContainer.'Zone Name'
                'Zone Type' = $zoneScopeContainer.'Zone Scope Container DN'
            }
        }

        $FailedZoneScopeContainerList += $AddToList
    }

    $FailedZoneScopeContainerList
}