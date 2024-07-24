function Get-BTDanglingSPN {
    <# Idea to make Get-BTDanglingSPN much faster:
        - First grab all of the SPNs
        - Check all of the hostnames:
            - Extract a list of all SPNs' hostnames and remove the resulting duplicate hostnames (so we can just validate hosts)
            - Check the deduplicated list of hostnames to see which ones resolve and then mark as pass/fail
            - Optional: also check those that resolve to see which ones respond (?)
            - For PowerShell 7+, use a parallel loop to speed up name resolution time even more
        - Compare the [list of SPNs] with [the list of hostnames that do not resolve] and use this as the dangling SPN list
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$Domains
    )

    if ($null -eq $Domains) {
        $Domains = Get-BTTarget
    }

    $danglingSPNList = @()

    foreach ($domain in $Domains) {
        # Get all objects w/SPNs
        $PrincipalWithSPN = Get-ADObject -Filter { ServicePrincipalName -ne "$null" -and ServicePrincipalName -ne 'kadmin/changepw' } -Properties * -Server $domain

        foreach ($principal in $PrincipalWithSPN) {
            # Get SPN hostname and check if DNS record exists
            foreach ($spn in $principal.ServicePrincipalName) {

                # Get SPN hostname
                $spnHost = $spn.Split('/')[1]

                # Regex filters out bare GUIDs. Intended for DCs, but need to add additional DC OU identification 
                if ($spnHost -notmatch '^[{]?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}[}]?$') {  
                    
                    # Check if DNS record exists for SPN hostname
                    $RRTypes = 'A', 'AAAA', 'TXT', 'CNAME'
                    $dnsResourceRecordExist = $false
                    $hostnameResolves = $false
                    foreach ($rrtype in $RRTypes) {
                        if (Get-DnsServerResourceRecord -ComputerName $domain -ZoneName $domain -RRType $rrtype -Name $spnHost -ErrorAction Ignore) {
                            $dnsResourceRecordExist = $true
                        }

                        if (Resolve-DnsName -Name $spnHost -Type $rrtype -ErrorAction Ignore) {
                            $hostnameResolves = $true
                        }

                        if ( $dnsResourceRecordExist -or $hostnameResolves ) {
                        } else {
                            $danglingSPN = [PSCustomObject]@{
                                Name  = $principal.Name
                                'Identity Reference' = ConvertTo-IdentityReference -SID $principal.objectSID
                                'Dangling SPN' = $spn
                                'Distinguished Name' = $principal.distinguishedName
                            }

                            if ( ($danglingSPNList.'Dangling SPN' -notcontains $danglingSPN.'Dangling SPN') ) {
                                $danglingSPNList += $danglingSPN
                            }
                        }
                    }
                }
            }
        }
    }
    $danglingSPNList
}
