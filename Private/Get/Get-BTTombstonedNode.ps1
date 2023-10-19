function Get-BTTombstonedNode {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$Domains
    )

    if ($null -eq $Domains) {
        $Domains = Get-BTTarget
    }

    $TombstonedNodeList = @()
    foreach ($domain in $Domains) {
        $domainDN = (Get-ADDomain $domain).DistinguishedName
        $Zones = Get-DnsServerZone -ComputerName $domain
        foreach ($zone in $Zones) {
            $Nodes = Get-DnsServerResourceRecord -ComputerName $domain -ZoneName $zone.ZoneName
            foreach ($node in $Nodes) {
                if ($node.DistinguishedName -like "*$domainDN") {
                    $nodeDetails = Get-ADObject -Identity $node.DistinguishedName -Properties dNSTombstoned -Server $domain
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