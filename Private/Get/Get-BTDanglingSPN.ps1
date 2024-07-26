function Get-BTDanglingSPN {
    <#
    .SYNOPSIS
    Get dangling SPNs from Active Directory.

    .DESCRIPTION
    Get dangling SPNs from all domains in an Active Directory forest. A dangling SPN is a SPN that references an unresolved hostname.

    .PARAMETER Domains
    The domain (or domains) to check for dangling SPNs. These can be entered as 'domain.com' or "@('domain1.com','domain2.com')".

    .EXAMPLE
    Get-BTDanglingSPN

    Get dangling SPNs in all domains in the current forest.

    .EXAMPLE
    Get-BTDanglingSPN -Domains 'domain.com'

    Get dangling SPNs in domain.com.

    .EXAMPLE
    Get-BTDanglingSPN -Domains @('domain1.com','domain2.com','domain3.com')

    Get danging SPNs in domain1.com, domain2.com, and domain3.com.

    .NOTES
    General notes
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$Domains
    )

    begin {
        # If no domains were specified, get all domains in the current forest.
        if ($null -eq $Domains) {
            $Domains = Get-BTTarget
        }

        # Define a RegEx for valid FQDNs.
        $RegexHostname = '^(?=^.{1,254}$)(^((?!-)[a-zA-Z0-9_-]{1,63}(?<!-)\.)+[a-zA-Z]{2,})$'

        # Initialize the hash tables (does making it ordered help performance?)
        $DanglingSPNList = [hashtable]@{}
        $DNSRecords = [ordered] @{}
    }

    process {
        # Cache all DNS records from all domains to make lookups faster. Will only need Resolve-DnsName for SPNs that refer to public names.
        # Keep this outside the other domain loop so all DNS records will be available for the entire script.
        Write-Host "[$(Get-Date -format 'yyyy-MM-dd hh:mm:ss')] Getting DNS records from all domains." -ForegroundColor White -BackgroundColor Black
        foreach ($domain in $Domains) {
            $DomainDNSRecords = Get-DnsServerResourceRecord -ComputerName $domain -ZoneName $domain -ErrorAction SilentlyContinue
            foreach ($record in $DomainDNSRecords) {
                $DNSRecords[$record.HostName] = $record.RecordData
            }
        }

        foreach ($domain in $Domains) {
            # Get all objects with SPNs.
            Write-Host "`n[$(Get-Date -format 'yyyy-MM-dd hh:mm:ss')] [$domain] Getting AD objects with SPNs." -ForegroundColor White -BackgroundColor Black
            $PrincipalWithSPN = Get-ADObject -Filter { ServicePrincipalName -ne "$null" -and ServicePrincipalName -ne 'kadmin/changepw' } -Properties * -Server $domain
            $PrincipalCount = $PrincipalWithSPN.Count
            Write-Host "[$(Get-Date -format 'yyyy-MM-dd hh:mm:ss')] [$domain] Found $PrincipalCount AD objects with SPNs." -ForegroundColor White -BackgroundColor Black

            # Loop through each security principal that has a SPN.
            $PrincipalProgress = 0
            foreach ($principal in $PrincipalWithSPN) {
                ++$PrincipalProgress
                Write-Verbose "[$(Get-Date -format 'yyyy-MM-dd hh:mm:ss')] [$domain] [$PrincipalProgress`/$PrincipalCount] [$($principal.CanonicalName)]"

                # Check each SPN to see if its hostname matches the principal's hostname.
                $CheckSPN = $false
                foreach ($spn in ($principal.serviceprincipalname)) {
                    # Remove the service name, the forward slash, and the port from the SPN to get its hostname.
                    $SPNHostname = ($spn).Split('/')[1].Split(':')[0]
                    $PrincipalHostname = $principal.DnsHostName

                    if ($SPNHostname -eq $PrincipalHostname) {
                        # If FQDNs match, ignore and $CheckSPN stays $false
                        Write-Verbose "$spn`n FQDN Match: `'$PrincipalHostname`' = `'$SPNHostname`'. [CheckSPN = $CheckSPN]"
                        continue
                    } elseif ("${SPNHostname}.${domain}" -eq $PrincipalHostname ) {
                        # Construct FQDN from SPNHostname + Domain and check for an FQDN match with PrincipalHostname.
                        Write-Verbose "`n Short Name Match: `'$PrincipalHostname`' = `'${SPNHostname}.${domain}`'. [CheckSPN = $CheckSPN]"
                        continue
                    } elseif ($SPNHostname -match '^[{]?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}[}]?$') {
                        # Do not inspect domain controller SPNs as long as they are in the DC OU.
                        ## NEED TO ADD EXTRA VALIDATION ##
                        Write-Verbose "`n Domain controller GUID. [CheckSPN = $CheckSPN]"
                        continue
                    } else {
                        # Flag the SPN for inspection if the ServicePrincipal hostname does not match any of the above conditions.
                        $CheckSPN = $true
                        $DnsResourceRecordExist = $false

                        Write-Host "`n[$(Get-Date -format 'yyyy-MM-dd hh:mm:ss')] [$domain] [$PrincipalProgress`/$PrincipalCount] Inspecting: $spn" -ForegroundColor Cyan
                        # Try to find the hostname in internal DNS zones.
                        if ($DNSRecords[$SPNHostname] -or $DNSRecords["${SPNHostname}.${domain}"]) {
                            # Chcek the cached internal DNS records for the hostname.
                            $DnsResourceRecordExist = $true
                            Write-Host "A DNS record was found for ${SPNHostname}." -ForegroundColor Green -BackgroundColor Black
                            continue
                        }

                        # Check for FQDNs not found in the internal $Domains list.
                        if ( ($SPNHostname -match $RegexHostname) -and -not (($domains | ForEach-Object {$SPNHostname.Contains($_)}) -contains $true) ) {
                            Write-Host "[$(Get-Date -format 'yyyy-MM-dd hh:mm:ss')] [$domain] [$PrincipalProgress`/$PrincipalCount] Checking external hostname: $SPNHostname" -ForegroundColor Cyan
                            # Try to resolve the external hostname.
                            if (Resolve-DnsName -Name $SPNHostname -ErrorAction SilentlyContinue) {
                                $DnsResourceRecordExist = $true
                                Write-Host "$SPNHostname was resolved externally." -ForegroundColor Cyan -BackgroundColor Black
                            } else {
                                # Might need more error handling, but basically the name didn't resolve and it is a dangling SPN.
                                $DnsResourceRecordExist = $false
                            }
                        }

                        # If a DNS record was not found, this is a dangling SPN.
                        if ( -not $DnsResourceRecordExist ) {
                            Write-Host "A DNS record for $SPNHostname was NOT FOUND." -ForegroundColor Red -BackgroundColor Black
                            $DanglingSPN = [PSCustomObject]@{
                                'PrincipalIdentityReference' = ConvertTo-IdentityReference -SID $principal.objectSID
                                'DanglingSPN' = $spn
                                'PrincipalDistinguishedName' = $principal.distinguishedName
                            }
                            # Avoid adding duplicates to the list (construct a unique key from the CN + SPN).
                            if ( -not $DanglingSPNList[ "$($principal.CanonicalName)`:$spn" ] ) {
                                $DanglingSPNList.Add( "$($principal.CanonicalName)`:$spn", $DanglingSPN )
                            }
                        }

                    } # end if/else hostname checks
                } # end foreach SPN
            } # end foreach principal
            Write-Host "$($PrincipalWithSPN.Count) principles found with SPNs in $domain." -ForegroundColor Cyan -BackgroundColor Black
        } # end foreach domain
    } # end process block

    end {
        # Return the results as an array (should I leave it as a hash table?).
        # Use optional parameters to write this to host, logfile, or clipboard.
        [array]$DanglingSPNList.Values
    } # end end block

} # end function
