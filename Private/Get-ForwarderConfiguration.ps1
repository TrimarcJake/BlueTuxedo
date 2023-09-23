function Get-ForwarderConfiguration {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]
        $Domains
    )

    $ForwarderList = @()
    foreach ($domain in $Domains) {
        $DNSServers = Resolve-DnsName -Type NS -Name $domain | Where-Object QueryType -eq 'A'
        foreach ($dnsServer in $DNSServers) {
            [array]$Forwarders = Get-DnsServerForwarder -ComputerName $dnsServer.IP4Address
            foreach ($forwarder in $Forwarders) {
                if ($ForwarderList.'Server IP' -notcontains $forwarder.IPAddress.IPAddressToString) {
                    $AddToList = [PSCustomObject]@{
                        'Server Name'   = $dnsServer.Name
                        'Server IP'     = $dnsServer.IP4Address
                        'Forwarders'    = $forwarder.IPAddress.IPAddressToString
                    }
                }

                $ForwarderList += $AddToList
            }
        }
    }

    $ForwarderList
}