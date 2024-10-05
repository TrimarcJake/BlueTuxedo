function Get-BTQueryResolutionPolicy {
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

    $QueryResolutionPolicyList = @()

    foreach ($dnsServer in $script:DNSServers) {

        # Enumerate the query resolution policies on each DNS server
        $QueryResolutionPolicies = (Get-DnsServer -ComputerName $dnsServer.IPAddress -ErrorAction Ignore -WarningAction Ignore).ServerPolicies

        # Add to the list if this DNS server's IP address is not already in the list.
        if ($QueryResolutionPolicyList.'Server IP' -notcontains $dnsServer.IPAddress) {
            foreach ($policy in $QueryResolutionPolicies) {
                $AddToList = [PSCustomObject]@{
                    'Server Name'          = $dnsServer.Name
                    'Server IP'            = $dnsServer.IPAddress
                    'QRP Name'             = $policy.Name
                    'QRP Level'            = $policy.Level
                    'QRP Processing Order' = $policy.ProcessingOrder
                    'QRP Enabled?'         = $policy.IsEnabled
                    'QRP Action'           = $policy.Action
                }

                $QueryResolutionPolicyList += $AddToList
            }
        }

    }

    $QueryResolutionPolicyList
}
