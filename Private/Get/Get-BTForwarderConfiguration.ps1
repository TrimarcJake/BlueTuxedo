function Get-BTForwarderConfiguration {
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

    $ForwarderList = @()

    foreach ($dnsServer in $script:DNSServers) {

        # Enumerate the forwarders on each DNS server
        [array]$Forwarders = Get-DnsServerForwarder -ComputerName $dnsServer.IPAddress

        # Add to the list if this DNS server's IP address is not already in the list.
        if ($ForwarderList.'Server IP' -notcontains $dnsServer.IPAddress) {
            foreach ($forwarder in $Forwarders) {
                $AddToList = [PSCustomObject]@{
                    'Server Name' = $dnsServer.Name
                    'Server IP'   = $dnsServer.IPAddress
                    'Forwarders'  = $forwarder.IPAddress.IPAddressToString
                }
            }

            $ForwarderList += $AddToList
        }
    }

    if ($ForwarderList.Count -lt 1) {
        Write-Host 'No forwarders were found.'
    }
    # Return the ForwarderList object
    $ForwarderList
}
