function Get-BTGlobalQueryBlockList {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$Domains,

        # Name of the DNS server[s] to exclude
        [Parameter()]
        [string[]]
        $Exclude
    )

    if ($null -eq $Domains) {
        $Domains = Get-BTTarget
    }

    if ($null -eq $script:DNSServers) {
        $script:DNSServers = Get-BTDnsServer -Domains $Domains -Exclude $Exclude
    }

    $GlobalQueryBlockListList = @()

    foreach ($dnsServer in $script:DNSServers) {

        # Enumerate the global query blocklists on each DNS server
        [array]$ServerGQBLs = Get-DnsServerGlobalQueryBlockList -ComputerName $dnsServer.IPAddress

        foreach ($gqbl in $ServerGQBLs) {
            # Add it to the list with server information
            $AddToList = [PSCustomObject]@{
                'Server Name' = $($dnsServer.Name)
                'Server IP'   = $($dnsServer.IPAddress)
                'Enabled?'    = $($gqbl.Enable)
                'GQBL'        = $($gqbl.List)
            }
            $GlobalQueryBlockListList += $AddToList
        }
    }

    if ($GlobalQueryBlockListList.Count -lt 1) {
        Write-Host 'No global query blocklists were found.'
    }
    # Return the GlobalQueryBlockList object
    $GlobalQueryBlockListList
}
