function Repair-BTThing {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$Things,
        [switch]$Run = $false
    )

    if ($null -eq $Things) {
        $Things = Get-BTThing
    }

    if ($Run) {
        foreach ($thing in $Things) {
            
        }
    } else {
        foreach ($thing in $Things) {
            Write-Host "DESCRIPTION OF CODE BLOCK" -ForegroundColor Green
            Write-Host @"
CODE BLOCK

"@
        }
    }
}