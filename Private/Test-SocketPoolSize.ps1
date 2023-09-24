function Test-SocketPoolSize {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$SocketPoolSizes
    )

    $FailedSocketPoolSize = @()
    foreach ($socketpoolsize in $SocketPoolSizes) {
        if ($socketpoolsize.'Socket Pool Size' -lt 100000) {
            $FailedSocketPoolSize += $socketpoolsize
        }
    }

    $FailedSocketPoolSize
}