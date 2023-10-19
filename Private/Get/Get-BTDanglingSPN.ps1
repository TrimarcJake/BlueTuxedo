function Get-BTDanglingSPN {
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
                                'Distinguished Name' = $principal.distinguishedName
                                'Dangling SPN' = $spn
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