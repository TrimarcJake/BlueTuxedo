function Export-Results {
    <#
    .SYNOPSIS
    Export the results to text files.

    .DESCRIPTION
    Export the results to text files.

    .PARAMETER Name
    Name of the file.

    .PARAMETER Data
    Data that will be exported to a file.

    .PARAMETER FilePath
    Path in which the file will be created.

    .EXAMPLE
    Export-Results -Name "Tested $item" -Data $TestedData.$Item

    #>
    [Cmdletbinding()]
    param (
        [string]$Name,
        $Data,
        [string]$FilePath = (Join-Path -Path $pwd -ChildPath "BlueTuxedo $Name $(Get-Date -f 'yyyyMMddhhmmss').txt")
    )

    Out-File -FilePath $FilePath -Encoding utf8 -InputObject $Data
}
