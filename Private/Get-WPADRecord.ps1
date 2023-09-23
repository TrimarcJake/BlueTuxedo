function Get-WPADRecord {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]
        $Domains
    )

    $WPADRecordList = @()
    foreach ($domain in $Domains) {
        $RRTypes = @('HInfo','Afsdb','Atma','Isdn','Key','Mb','Md','Mf','Mg','MInfo','Mr','Mx','NsNxt','Rp','Rt','Wks','X25','A',
        'AAAA','CName','Ptr','Srv','Txt','Wins','WinsR','Ns','Soa','NasP','NasPtr','DName','Gpos','Loc','DhcId','Naptr','RRSig',
        'DnsKey','DS','NSec','NSec3','NSec3Param','Tlsa')
        $WPADExists = $false
        foreach ($rrtype in $RRTypes) {
            if (Get-DnsServerResourceRecord -ComputerName $domain -ZoneName $domain -RRType $rrtype -Name 'wpad' -ErrorAction Ignore) {
                $WPADExists = $true
                $ActualRRType = $rrtype
            }
        }

        if ($WPADExists -eq $true) {
            $AddToList = [PSCustomObject]@{
                'Domain'           = $domain
                'WPAD Exists?' = $true
                'WPAD Type'    = $ActualRRType
            } 
        } else {
            $AddToList = [PSCustomObject]@{
                'Domain'           = $domain
                'WPAD Exists?' = $false
                'WPAD Type'    = 'N/A'
            }
        }
        
        $WPADRecordList += $AddToList
    }

    $WPADRecordList
}