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
    $DHCPServers = Get-DhcpServerInDC
    foreach ($dhcpserver in $DHCPServers) {
        $DynamicUpdateServiceAccounts = try {
            Get-DhcpServerDnsCredential -ComputerName $dhcpserver.IPAddress 
        } catch {
            [PSCustomObject]@{
                UserName   = 'Not Configured'
                DomainName = 'N/A'
            }
        }
        
        if ($DynamicUpdateServiceAccountList.'Server IP' -notcontains $dhcpserver.IPAddress) {
            foreach ($account in $DynamicUpdateServiceAccounts) {
                $AddToList = [PSCustomObject]@{
                    'Server Name'            = $dhcpserver.dnsName
                    'Server IP'              = $dhcpserver.IPAddress
                    'Service Account Name'   = $account.UserName
                    'Service Account Domain' = $account.DomainName
                }
                
                $DynamicUpdateServiceAccountList += $AddToList
            }
        }
    }

    $DynamicUpdateServiceAccountList
}