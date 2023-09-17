function Invoke-BlueTuxedo {
    # param(
    #     $Forest
    # )
    $Domains = (Get-ADForest).Domains
    Get-DanglingSPN $Domains
}