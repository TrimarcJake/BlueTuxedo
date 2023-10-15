function Repair-BTTombstonedNode {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$TombstonedNodes,
        [switch]$Run = $false
    )

    if ($null -eq $TombstonedNodes) {
        $TombstonedNodes = Get-BTTombstonedNode
    }

    if ($Run) {
        foreach ($tombstonednode in $TombstonedNodes) {
            Remove-ADObject $tombstonednode.'Node DN'
        }
    } else {
        foreach ($tombstonednode in $TombstonedNodes) {
            Write-Host "Run the following code block to delete the $($tombstonednode.'Node Name') node from the $($tombstonednode.'Zonee Name') zone." -ForegroundColor Green
            Write-Host @"
Remove-ADObject '$($tombstonednode.'Node DN')'

"@
        }
    }
}