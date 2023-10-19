function Show-BTFixes {
    [CmdletBinding()]
    param (
        [ValidateSet(
            'All',
            'SocketPoolSizes',
            'TombstonedNodes',
            'WildcardRecords',
            'WPADRecords'
        )]
        [string]$Section = 'All',
        [switch]$ShowSecurityDescriptors = $false
    )

    $Sections = @(
        'SocketPoolSizes',
        'TombstonedNodes',
        'WildcardRecords',
        'WPADRecords'
    )

    $TitleHashtable = @{
        'Section' = 'Friendly Name'
        'SocketPoolSizes' = 'Set Socket Pool Size To Maximum'
        'TombstonedNodes' = 'Delete All Tombstoned Nodes'
        'WildcardRecords' = 'Fix Wildcard Record Configuration by Domain'
        'WPADRecords' = 'Fix WPAD Record Configuration by Domain'
    }

    if ($ShowSecurityDescriptors) {
        $Sections += 'SecurityDescriptors'
    }
    
    if ($Section = 'All') {
        foreach ($entry in $Sections) {
            $Title = $TitleHashtable[$entry]
            $SectionScriptBlock = "Repair-BT$entry"
            $SectionScriptBlock = $SectionScriptBlock.TrimEnd('s')
            Clear-Host
            Write-Host "/--------------- $Title ---------------\" -ForegroundColor Green
            $ScriptBlock = [scriptblock]::Create($SectionScriptBlock)
            Invoke-Command -ScriptBlock $ScriptBlock
            Write-Host "\--------------- $Title ---------------/" -ForegroundColor Green
            Read-Host "Press Enter to load the next section"
        }
    } else {
        $Title = $TitleHashtable[$Section]
        $SectionScriptBlock = "Repair-$Title"+"s" 
        Clear-Host
        Write-Host "/--------------- $Title ---------------\" -ForegroundColor Green
        $ScriptBlock = [scriptblock]::Create($SectionScriptBlock)
        Invoke-Command -ScriptBlock $ScriptBlock
        Write-Host "\--------------- $Title ---------------/" -ForegroundColor Green
    }
}