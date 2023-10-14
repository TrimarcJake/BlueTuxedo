function Test-SocketPoolSize {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$SocketPoolSizes
    )

    if ($null -eq $SocketPoolSizes) {
        $SocketPoolSizes = Get-SocketPoolSize
    }

    $FailedSocketPoolSize = @()
    foreach ($socketpoolsize in $SocketPoolSizes) {
        if ($socketpoolsize.'Socket Pool Size' -lt 10000) {
            $FailedSocketPoolSize += $socketpoolsize
        }
    }

    $FailedSocketPoolSize
}