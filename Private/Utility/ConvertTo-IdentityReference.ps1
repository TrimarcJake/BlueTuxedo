function ConvertTo-IdentityReference {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $SID
    )

    $Principal = New-Object System.Security.Principal.SecurityIdentifier($SID)
    $IdentityReference = $Principal.Translate([System.Security.Principal.NTAccount]).Value
    $IdentityReference
}