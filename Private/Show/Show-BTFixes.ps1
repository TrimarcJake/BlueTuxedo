function Show-BTFixes {
    [CmdletBinding()]
    param (
        [switch]$ShowSecurityDescriptors = $false,
        [switch]$Demo,
        [ValidateSet(
            'All',
            'TestedSocketPoolSizes',
            'TombstonedNodes',
            'TestedWildcardRecords',
            'TestedWPADRecords',
            'DanglingSPNs',
            'TestedADILegacyZones'
        )]
        [string]$Section = 'All',
        $ConditionalForwarders,
        $DanglingSPNs,
        $DnsAdminsMemberships,
        $DnsUpdateProxyMemberships,
        $NonADIZones,
        $QueryResolutionPolicys,
        $TombstonedNodes,
        $ZoneScopes,
        $TestedADILegacyZones,
        $TestedADIInsecureUpdateZones,
        $TestedDynamicUpdateServiceAccounts,
        $TestedForwarderConfigurations,
        $TestedGlobalQueryBlockLists,
        $TestedSecurityDescriptorACEs,
        $TestedSecurityDescriptorOwners,
        $TestedSocketPoolSizes,
        $TestedWildcardRecords,
        $TestedWPADRecords,
        $TestedZoneScopeContainers
    )

    $Sections = @(
        'TestedSocketPoolSizes',
        'TombstonedNodes',
        'TestedWildcardRecords',
        'TestedWPADRecords',
        'DanglingSPNs',
        'TestedADILegacyZones'
    )

    $TitleHashtable = @{
        'Section' = 'Friendly Name'
        'TestedSocketPoolSizes' = 'Set Socket Pool Size To Maximum'
        'TombstonedNodes' = 'Delete All Tombstoned Nodes'
        'TestedWildcardRecords' = 'Fix Wildcard Record Configuration by Domain'
        'TestedWPADRecords' = 'Fix WPAD Record Configuration by Domain'
        'DanglingSPNs' = 'Delete Dangling SPNs'
        'TestedADILegacyZones' = 'Convert Legacy Zones to ForestDNS Zones'
    }

    if ($ShowSecurityDescriptors) {
        $Sections += 'SecurityDescriptors'
    }
    
    if ($Section = 'All') {
        foreach ($entry in $Sections) {
            $Title = $TitleHashtable[$entry]
            if ($null -ne (Get-Variable $entry).Value) {
                $SectionScriptBlock = "Repair-BT$entry"
                $SectionScriptBlock = $SectionScriptBlock.TrimEnd('s') + " -$entry `$$entry"

                Write-Host "entry: $entry`nScriptBlock: $SectionScriptBlock"; Pause
                if ($Demo) { Clear-Host }
                Write-Host "/--------------- $Title ---------------\" -ForegroundColor Green
                $ScriptBlock = [scriptblock]::Create($SectionScriptBlock)
                Invoke-Command -ScriptBlock $ScriptBlock
                Write-Host "\--------------- $Title ---------------/" -ForegroundColor Green
                Read-Host "Press Enter to load the next section"
            }
        }
    } else {
        $Title = $TitleHashtable[$Section]
        if ($Demo) { Clear-Host }
        Write-Host "/--------------- $Title ---------------\" -ForegroundColor Green
        if ($null -eq (Get-Variable $Section).Value) {
            Write-Host "No data collected for $Title" -ForegroundColor Yellow
        }
        else {
            $SectionScriptBlock = "Repair-BT$Section"
            $SectionScriptBlock = $SectionScriptBlock.TrimEnd('s') + " -$Section `$$Section"
            $ScriptBlock = [scriptblock]::Create($SectionScriptBlock)
            Invoke-Command -ScriptBlock $ScriptBlock
        }
        Write-Host "\--------------- $Title ---------------/" -ForegroundColor Green
    }
}