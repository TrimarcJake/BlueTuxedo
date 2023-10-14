function Get-BTDynamicUpdateServiceAccount {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$Domains
    )

    if ($null -eq $Domains) {
        $Domains = Get-BTTarget
    }

    $DynamicUpdateServiceAccountList = @()
    foreach ($domain in $Domains) {
        $DNSServers = Resolve-DnsName -Type NS -Name $domain | Where-Object QueryType -eq 'A'
        foreach ($dnsServer in $DNSServers) {
            $DynamicUpdateServiceAccounts = try {
                Get-DhcpServerDnsCredential -ComputerName $dnsServer.IP4Address 
            } catch {
                [PSCustomObject]@{
                    UserName   = 'Not Configured'
                    DomainName = 'N/A'
                }
            }
            
            if ($DynamicUpdateServiceAccountList.'Server IP' -notcontains $dnsServer.IP4Address) {
                foreach ($account in $DynamicUpdateServiceAccounts) {
                    $AddToList = [PSCustomObject]@{
                        'Server Name'            = $dnsServer.Name
                        'Server IP'              = $dnsServer.IP4Address
                        'Service Account Name'   = $account.UserName
                        'Service Account Domain' = $account.DomainName
                    }
                    
                    $DynamicUpdateServiceAccountList += $AddToList
                }
            }
        }
    }

    $DynamicUpdateServiceAccountList
}