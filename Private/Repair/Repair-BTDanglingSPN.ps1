function Repair-BTDanglingSPN {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$DanglingSPNs,
        [switch]$Run = $false
    )

    if ($null -eq $DanglingSPNs) {
        # $DanglingSPNs = Get-BTDanglingSPN
        return
    }

    if ($Run) {
        foreach ($danglingspn in $DanglingSPNs) {
            setspn -d $danglingspn.'Dangling SPN' $danglingspn.'Identity Reference'
        }
    } else {
        foreach ($danglingspn in $DanglingSPNs) {
            Write-Host "Run the following code block to delete the identified Dangling SPN" -ForegroundColor Green
            Write-Host "SPN: $($danglingspn.'Dangling SPN')" -ForegroundColor Green
            Write-Host "Principal: $($danglingspn.'Identity Reference')" -ForegroundColor Green
            Write-Host "setspn -d $($danglingspn.'Dangling SPN') $($danglingspn.'Identity Reference')"
            Write-Host
        }
    }
}
