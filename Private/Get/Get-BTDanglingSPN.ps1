function Get-BTDanglingSPN {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$Domains
    )

    # If no domains were specified, get all domains in the current forest.
    if ($null -eq $Domains) {
        $Domains = Get-BTTarget
    }

    # Initialize the DanglingSPNList with a hash table or an [ordered] one:
    $DanglingSPNList = [hashtable]@{}
    # Define a RegEx for valid FQDNs.
    $RegexHostname = '^(?=^.{1,254}$)(^((?!-)[a-zA-Z0-9_-]{1,63}(?<!-)\.)+[a-zA-Z]{2,})$'

    # Cache all DNS records from all domains to make lookups faster. Will only need Resolve-DnsName for SPNs that refer to public names.
    # Keeping this outside the other domain loop so all DNS records will be available for the entire script.
    Write-Host "[$(Get-Date -format 'yyyy-MM-dd hh:mm:ss')] Getting DNS records from all domains." -ForegroundColor White -BackgroundColor Black
    $DNSRecords = [ordered] @{}
    foreach ($domain in $Domains) {
        $DomainDNSRecords = Get-DnsServerResourceRecord -ComputerName $domain -ZoneName $domain -ErrorAction SilentlyContinue
        foreach ($DNS in $DomainDNSRecords) {
            $DNSRecords[$DNS.HostName] = $DNS.RecordData.IPV4Address
        }
    }

    # Analyze all SPNs in each domain.
    foreach ($domain in $Domains) {
        # Get all objects with SPNs.
        Write-Host "`n[$(Get-Date -format 'yyyy-MM-dd hh:mm:ss')] [$domain] Getting AD objects with SPNs." -ForegroundColor White -BackgroundColor Black
        $PrincipalWithSPN = Get-ADObject -Filter { ServicePrincipalName -ne "$null" -and ServicePrincipalName -ne 'kadmin/changepw' } -Properties * -Server $domain
        $PrincipalCount = $PrincipalWithSPN.Count
        Write-Host "[$(Get-Date -format 'yyyy-MM-dd hh:mm:ss')] [$domain] Found $PrincipalCount AD objects with SPNs." -ForegroundColor White -BackgroundColor Black

        $PrincipalProgress = 0
        foreach ($principal in $PrincipalWithSPN) {
            ++$PrincipalProgress
            Write-Verbose "[$(Get-Date -format 'yyyy-MM-dd hh:mm:ss')] [$domain] [$PrincipalProgress`/$PrincipalCount] [$($principal.CanonicalName)]"

            #region HostNameMatch
            # Skip this principal if the hostname in each SPN matches the principal's hostname.
            $CheckSPN = $false
            foreach ($spn in ($principal.serviceprincipalname)) {
                # Remove the service name, the forward slash, and the port from the SPN to get its hostname.
                $SPHostName = ($spn).Split('/')[1].Split(':')[0]
                $PrincipalHostname = $principal.DnsHostName

                if ($SPHostName -eq $PrincipalHostname) {
                    # If FQDNs match, $CheckSPN stays $false
                    Write-Verbose "$spn`n FQDN Match: `'$PrincipalHostname`' = `'$SPHostName`'. [CheckSPN = $CheckSPN]"
                } elseif ("${SPHostName}.${domain}" -eq $PrincipalHostname ) {
                    # Construct FQDN from SPHostName+Domain and check for FQDN match with PrincipalHostname.
                    Write-Verbose "`n Short Name Match: `'$PrincipalHostname`' = `'${SPHostName}.${domain}`'. [CheckSPN = $CheckSPN]"
                } elseif ($SPHostName -match '^[{]?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}[}]?$') {
                    # Do not inspect domain controller SPNs as long as they are in the DC OU.
                    ## NEED TO ADD EXTRA VALIDATION ##
                    Write-Verbose "`n Domain controller GUID. [CheckSPN = $CheckSPN]"
                } else {
                    # Flag the SPN for inspection if the ServicePrincipal hostname does not match any of the above conditions.
                    $CheckSPN = $true
                    Write-Host "`n[$(Get-Date -format 'yyyy-MM-dd hh:mm:ss')] [$domain] [$PrincipalProgress`/$PrincipalCount] Inspecting: $spn" -ForegroundColor Cyan
                }
            }
            #endregion HostNameMatch

            if (-not $CheckSPN) {
                # If this principal is not flagged for inspection, continue to the next one in the loop.
                continue
            }

            #region CheckExternalHostname
            # Check if $SPHostName is an FQDN that does not contain any internal domain names.
            if ( ($SPHostName -match $RegexHostname) -and -not (($domains | ForEach-Object {$SPHostName.Contains($_)}) -contains $true) ) {
                # Lookup external address
                if (Resolve-DnsName -Name $SPHostName -ErrorAction SilentlyContinue) {
                    # Not a dangling SPN.
                    $CheckSPN = $false
                    Write-Host "$SPHostName was resolved externally." -ForegroundColor Cyan -BackgroundColor Black
                } else {
                    # Might need more error handling, but basically it's a dangling SPN because the name didn't resolve.
                    $CheckSPN = $true
                }
            }
            #endregion CheckExternalHostname

            if (-not $CheckSPN) {
                # If this principal is not flagged for inspection, continue to the next one in the loop.
                continue
            }

            # Get SPN hostname and check if DNS record exists
            foreach ($spn in $principal.ServicePrincipalName) {
                # Get SPN hostname
                $SPHostName = ($spn).Split('/')[1].Split(':')[0]

                # Check if DNS record exists for SPN hostname
                $DnsResourceRecordExist = $false

                # Try to find or resolve the hostname in DNS
                if ($DNSRecords[$SPHostName] -or $DNSRecords["${SPHostName}.${domain}"]) {
                    $DnsResourceRecordExist = $true
                }

                # If neither of the above are true, this is a dangling SPN.
                # if ( $DnsResourceRecordExist -or $HostnameResolves ) {
                if ( $DnsResourceRecordExist ) {
                    Write-Host "A DNS record was found for ${SPHostName}." -ForegroundColor Green -BackgroundColor Black
                    continue
                } else {
                    Write-Host "A DNS record for $SPHostName was NOT FOUND." -ForegroundColor Red -BackgroundColor Black
                    $DanglingSPN = [PSCustomObject]@{
                        'Name'  = $principal.Name
                        'IdentityReference' = ConvertTo-IdentityReference -SID $principal.objectSID
                        'DanglingSPN' = $spn
                        'DistinguishedName' = $principal.distinguishedName
                    }
                    # Avoid adding duplicates
                    <#
                    if ( ($DanglingSPNList.'DanglingSPN' -notcontains $DanglingSPN.'DanglingSPN') ) {
                        Write-Verbose "[$(Get-Date -format 'yyyy-MM-dd hh:mm:ss')] [$domain] [$PrincipalProgress`/$PrincipalCount] Dangling SPN added for $SPHostName."
                        $DanglingSPNList.Add($DanglingSPN)
                    }
                    #>
                    if ( -not $DanglingSPNList[$($spn.DistinguishedName)] ) {
                        $DanglingSPNList.Add( $($spn.DistinguishedName), $DanglingSPN )
                    }
                }
            } # end foreach SPN
        } # end foreach principal
        Write-Host "$($PrincipalWithSPN.Count) principles found with SPNs in $domain." -ForegroundColor Cyan -BackgroundColor Black
    } # end foreach domain
    $DanglingSPNList
} # end function
