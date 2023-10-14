function Test-BTZoneScopeContainer {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$ZoneScopeContainers
    )

    if ($null -eq $ZoneScopeContainers) {
        $ZoneScopeContainers = Get-BTZoneScopeContainer
    }

    $FailedZoneScopeContainerList = @()

    foreach ($zoneScopeContainer in $ZoneScopeContainers) {
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