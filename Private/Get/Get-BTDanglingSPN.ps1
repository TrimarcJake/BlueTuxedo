function Get-BTDanglingSPN {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$Domains
    )

    if ($null -eq $Domains) {
        $Domains = Get-BTTarget
    }

    # Initialize the DanglingSPNList
    [System.Collections.Generic.List[PSCustomObject]]$DanglingSPNList = @()

    # Cache all DNS records from all domains to make lookups faster. Won't need Get-DnsServerResourceRecord or Resolve-DnsName.
    # This is outside the next domain loop so all records will be available for the rest of the script.
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
        $PrincipalProgress = 0
        foreach ($principal in $PrincipalWithSPN) {
            ++$PrincipalProgress
            Write-Verbose "[$(Get-Date -format 'yyyy-MM-dd hh:mm:ss')] [$domain] [$PrincipalProgress`/$PrincipalCount] [$($principal.CanonicalName)]"

            #region HostnameMatch
            # Skip this principal if the hostname in each SPN matches the principal's hostname.
            $CheckSPN = $false
            foreach ($spn in ($principal.serviceprincipalname)) {
                $PrincipalHostname = $principal.DnsHostName
                # Remove the service name, the forward slash, and the port from the SPN to get its hostname.
                $SPHostName = ($spn).Split('/')[1].Split(':')[0]
                if ($SPHostName -eq $PrincipalHostname) {
                    # Check if FQDNs match
                    #$CheckSPN = $false
                    Write-Verbose "$spn`n FQDN Match: `'$PrincipalHostname`' = `'$SPHostName`'. [CheckSPN = $CheckSPN]"
                } elseif ( $($SPHostName+".$domain") -eq $PrincipalHostname ) {
                    # Handle SPNs with short names for the host
                    #$CheckSPN = $false
                    Write-Verbose "`n Short Name Match: `'$PrincipalHostname`' = `'$($SPHostName+".$domain")`'. [CheckSPN = $CheckSPN]"
                } elseif ($SPHostName -match '^[{]?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}[}]?$') {
                    # Do not inspect domain controller SPNs as long as they are in the DC OU.
                    #$CheckSPN = $false
                    Write-Verbose "`n Domain controller GUID. [CheckSPN = $CheckSPN]"
                } else {
                    # If the ServicePrincipal hostname does not match the principal's hostname, flag for inspection.
                    $CheckSPN = $true
                    Write-Host "`n[$(Get-Date -format 'yyyy-MM-dd hh:mm:ss')] [$domain] [$PrincipalProgress`/$PrincipalCount] Inspecting: $spn" -ForegroundColor Cyan
                }
            }
            if (-not $CheckSPN) {
                # If this principal is not flagged for inspection, continue to the next one.
                continue
            }
            #endregion HostnameMatch

            if ($CheckSPN) {
                # Get SPN hostname and check if DNS record exists
                foreach ($spn in $principal.ServicePrincipalName) {
                    # Get SPN hostname
                    $SPHostName = ($spn).Split('/')[1].Split(':')[0]

                    # Check if DNS record exists for SPN hostname
                    $DnsResourceRecordExist = $false
                    #$HostnameResolves = $false

                    # Try to find or resolve the hostname in DNS
                    if ($DNSRecords[$SPHostName]) {
                        $DnsResourceRecordExist = $true
                    }
                    <# Won't need this if the above check for "cached" DNS records works!
                    if (Get-DnsServerResourceRecord -ComputerName $domain -ZoneName $domain -Name $SPHostName -ErrorAction Ignore) {
                        $DnsResourceRecordExist = $true
                    } elseif (Resolve-DnsName -Name $SPHostName -QuickTimeout -ErrorAction Ignore) {
                        $HostnameResolves = $true
                    } else {
                        # Could track $Failed and automatically mark the rest of the SPNs on this principal as "dangling."
                    }
                    #>

                    # If neither of the above are true, this is a dangling SPN.
                    # if ( $DnsResourceRecordExist -or $HostnameResolves ) {
                    if ( $DnsResourceRecordExist ) {
                        Write-Host "$SPHostName resolved OK." -ForegroundColor Green -BackgroundColor Black
                        continue
                    } else {
                        Write-Host "$SPHostName NOT resolved." -ForegroundColor Red -BackgroundColor Black
                        $DanglingSPN = [PSCustomObject]@{
                            'Name'  = $principal.Name
                            'IdentityReference' = ConvertTo-IdentityReference -SID $principal.objectSID
                            'DanglingSPN' = $spn
                            'DistinguishedName' = $principal.distinguishedName
                        }
                        # Avoid adding duplicates
                        if ( ($DanglingSPNList.'DanglingSPN' -notcontains $DanglingSPN.'DanglingSPN') ) {
                            Write-Verbose "[$(Get-Date -format 'yyyy-MM-dd hh:mm:ss')] [$domain] [$PrincipalProgress`/$PrincipalCount] Dangling SPN added for $SPHostName."
                            $DanglingSPNList.Add($DanglingSPN)
                        }
                    }
                } # end foreach SPN
            } # end if CheckSPN
        } # end foreach principal
        Write-Host "$($PrincipalWithSPN.Count) principles found with SPNs in $domain." -ForegroundColor Cyan -BackgroundColor Black
    } # end foreach domain
    $danglingSPNList
} # end function
