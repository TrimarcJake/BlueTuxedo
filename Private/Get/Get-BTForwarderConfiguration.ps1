function Get-BTForwarderConfiguration {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$Domains
    )

    if ($null -eq $Domains) {
        $Domains = Get-BTTarget
    }

    $ForwarderList = @()
    foreach ($domain in $Domains) {
        $DNSServers = Resolve-DnsName -Type NS -Name $domain | Where-Object QueryType -eq 'A'
        foreach ($dnsServer in $DNSServers) {
            [array]$Forwarders = Get-DnsServerForwarder -ComputerName $dnsServer.IP4Address
            if ($ForwarderList.'Server IP' -notcontains $dnsServer.IP4Address) {
                foreach ($forwarder in $Forwarders) {
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