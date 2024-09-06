function Get-BTDnsServers {
    [CmdletBinding()]
    param (
        # Domains to inspect
        [Parameter()]
        [array]$Domains,

        # Name server to exclude
        [Parameter()]
        [string[]]
        $Exclude
    )

    if ($null -eq $Domains) {
        $Domains = Get-BTTarget
    }

    if ($PSBoundParameters.Keys.Contains('Exclude')) {
        # Exclude certain name server[s]
        [string[]]$ExcludeList = @()
        foreach ($item in $Exclude) {
            foreach ($domain in $Domains) {
                # Normalize the server name to an FQDN
                if ($item -match "$($domain)$") {
                    $ExcludeList += $item
                } else {
                    $ExcludeList += "$item.${domain}"
                }
                # This could more precisely get the proper FQDN but works for now
            }
        }
        Write-Verbose "Excluding: $($ExcludeList -join ',')"
    }

    $DnsServerList = @()

    # Loop through each domain
    foreach ($domain in $Domains) {

        # Find and loop through each DNS server
        $DNSServers = Resolve-DnsName -Type NS -Name $domain | Where-Object { $ExcludeList -notin $_.Name } | Where-Object { $_.QueryType -eq 'A' } | Sort-Object Name
        $DnsServerList += $DNSServers
    }

    Write-Verbose "Found $($DNSServers.Count) DNS servers in $($Domains.Count) domains."
    $DnsServerList
}
