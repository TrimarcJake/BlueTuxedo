function Get-Target {
    param (
        [string]$Forest = (Get-ADForest).Name,
        [string]$InputPath
    )

    if ($InputPath) {
        $Targets = Get-Content $InputPath
    } else {
        $Targets = (Get-ADForest $Forest).Domains
    }
    
    $Targets
}