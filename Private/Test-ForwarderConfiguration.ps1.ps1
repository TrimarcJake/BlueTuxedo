function Test-ForwarderConfiguration {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$ForwarderConfigurations
    )

    $FailedForwarderConfiguration = @()
    $ForwarderHashtable = @{
        'AdGuard Primary'                               = '94.140.14.14'
        'AdGuard Secondary'                             = '94.140.15.15'  
        'Alternate Primary'                             = '76.76.19.19'   
        'Alternate Secondary'                           = '76.223.122.150'
        'CleanBrowsing Primary'                         = '185.228.168.9'  
        'CleanBrowsing Secondary'                       = '185.228.169.9' 
        'Cloudflare Primary'                            = '1.1.1.1'       
        'Cloudflare Secondary'                          = '1.0.0.1'
        'Cloudflare Primary (Malware Filtered)'         = '1.1.1.1'       
        'Cloudflare Secondary (Malware Filtered)'       = '1.0.0.1'
        'Cloudflare Primary (Malware/Adult Filtered)'   = '1.1.1.1'       
        'Cloudflare Secondary (Malware/Adult Filtered)' = '1.0.0.1'
        'Comodo Secure Primary'                         = '8.26.56.26'     
        'Comodo Secure Secondary'                       = '8.20.247.20'
        'Control D Primary'                             = '76.76.2.0'   
        'Control D Secondary'                           = '76.76.10.0'
        'Google Primary'                                = '8.8.8.8'       
        'Google Secondary'                              = '8.8.4.4'
        'OpenDNS Home Primary'                          = '208.67.222.222'
        'OpenDNS Home Secondary'                        = '208.67.220.220'
        'Quad9 Primary'                                 = '9.9.9.9'      
        'Quad9 Secondary'                               = '149.112.112.112'
    }
    foreach ($forwarderconfiguration in $ForwarderConfigurations) {
        foreach ($forwarder in $forwarderconfiguration.Forwarders) {
            $resolveForwarder = Resolve-DnsName -Name $forwarder -ErrorAction Ignore
            $forwarderName = 'N/A'
            $wellKnown = $false
            $wellKnownName = 'N/A'
            if ($resolveForwarder) {
                $forwarderName = $resolveForwarder.NameHost
                foreach ($h in $ForwarderHashtable.GetEnumerator() ) {
                    if ($h.Value -eq $forwarder) {
                        $wellKnown = $true
                        $wellKnownName = $h.Name
                    }
                }
            }
            $AddToList = [PSCustomObject]@{
                'Server Name'    = $forwarderconfiguration.'Server Name'
                'Server IP'      = $forwarderconfiguration.'Server IP'
                'Forwarder IP'   = $forwarder
                'Forwarder Name' = $forwarderName
                'Well-Known?'    = $wellKnown
                'Service'        = $wellKnownName
            }

            $FailedForwarderConfiguration += $AddToList
        }
    }

    $FailedForwarderConfiguration
}