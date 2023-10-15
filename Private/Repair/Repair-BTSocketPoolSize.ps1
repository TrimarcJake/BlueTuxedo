function Repair-BTSocketPoolSize {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$TestedSocketPoolSizes,
        [switch]$Run = $false
    )

    if ($null -eq $TestedSocketPoolSizes) {
        $TestedSocketPoolSizes = Test-BTSocketPoolSize
    }

    if ($Run) {
        foreach ($testedsocketpoolsize in $TestedSocketPoolSizes) {
            $Settings = Get-DnsServerSetting -ComputerName $testedsocketpoolsize.'Server IP' -All
            $Settings.SocketPoolSize = 10000
            Set-DnsServerSetting -ComputerName $testedsocketpoolsize.'Server IP' -InputObject $Settings
        }
    } else {
        foreach ($testedsocketpoolsize in $TestedSocketPoolSizes) {
            Write-Host "Run the following code block to set DNS Server $($testedsocketpoolsize.'Server IP') Socket Pool Size to 10,000:" -ForegroundColor Green
            Write-Host @"
`$Settings = Get-DnsServerSetting -ComputerName $($testedsocketpoolsize.'Server IP') -All
`$Settings.SocketPoolSize = 10000
Set-DnsServerSetting -ComputerName $($testedsocketpoolsize.'Server IP') -InputObject `$Settings

"@
        }
    }
}