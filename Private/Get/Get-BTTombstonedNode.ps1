function Get-BTTombstonedNode {
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

    $TombstonedNodeList = @()

    foreach ($domain in $Domains) {
        $domainDN = (Get-ADDomain $domain).DistinguishedName
        $Zones = Get-DnsServerZone -ComputerName $domain
        foreach ($zone in $Zones) {
            $Nodes = Get-DnsServerResourceRecord -ComputerName $domain -ZoneName $zone.ZoneName
            foreach ($node in $Nodes) {
                if ($node.DistinguishedName -like "*$domainDN") {
                    try {
                        $nodeDetails = Get-ADObject -Identity $node.DistinguishedName -Properties dNSTombstoned -Server $domain
                    } catch {
                        Write-Verbose "Unable to find tombstoned node $($node.DistinguishedName)" -Verbose
                    }
                }
                if ($nodeDetails.dNSTombstoned) {
                    $AddToList = [PSCustomObject]@{
                        'Zone Name'   = $zone.ZoneName
                        'Node Name'   = $node.HostName
                        'Record Type' = $node.RecordType
                        'Node DN'     = $node.DistinguishedName
                    }

                    $TombstonedNodeList += $AddToList
                }
            }
        }
    }

    $TombstonedNodeList
}
