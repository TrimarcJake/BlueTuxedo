function Repair-BTTestedWildcardRecord {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$TestedWildcardRecords,
        [switch]$Run = $false
    )

    if ($null -eq $TestedWildcardRecords) {
        $TestedWildcardRecords = Test-BTWildcardRecord
    }

    if ($Run) {
        foreach ($wildcardrecord in $TestedWildcardRecords) {
            $type = "-$($wildcardrecord.'Correct Type')"
            if ($wildcardrecord.'Wildcard Exists?') {
                Remove-DnsServerResourceRecord -ComputerName $wildcardrecord.Domain -ZoneName $wildcardrecord.Domain -RRType $wildcardrecord.'Current Wildcard Type' -Name '*'
            }
            if ($type -eq '-Txt') {
                $AddWildcardScriptBlock = "Add-DnsServerResourceRecord -ComputerName $($wildcardrecord.Domain) -ZoneName $($wildcardrecord.Domain) $type -Name '*' -DescriptiveText '0.0.0.0'"
            } elseif ($type -eq '-A') {
                $AddWildcardScriptBlock = "Add-DnsServerResourceRecord -ComputerName $($wildcardrecord.Domain) -ZoneName $($wildcardrecord.Domain) $type -Name '*' -RecordData '0.0.0.0'"
            }
            $ScriptBlock = [scriptblock]::Create($AddWildcardScriptBlock)
            Invoke-Command -ScriptBlock $ScriptBlock
        }
    } else {
        foreach ($wildcardrecord in $TestedWildcardRecords) {
            $type = "-$($wildcardrecord.'Correct Type')"
            if ($wildcardrecord.'Wildcard Exists?') {
                Write-Host "Run the following code block to delete the Wildcard Record of incorrect type ($($wildcardrecord.'Current Wildcard Type')) and replace with a Wildcard Record of the correct type ($type) in the $($wildcardrecord.Domain) domain" -ForegroundColor Green
                if ($type -eq '-Txt') {
                    $AddWildcardScriptBlock = "Add-DnsServerResourceRecord -ComputerName $($wildcardrecord.Domain) -ZoneName $($wildcardrecord.Domain) $type -Name '*' -DescriptiveText '0.0.0.0'"
                } elseif ($type -eq '-A') {
                    $AddWildcardScriptBlock = "Add-DnsServerResourceRecord -ComputerName $($wildcardrecord.Domain) -ZoneName $($wildcardrecord.Domain) $type -Name '*' -RecordData '0.0.0.0'"
                }
                Write-Host @"
Remove-DnsServerResourceRecord -ComputerName $($wildcardrecord.Domain) -ZoneName $($wildcardrecord.Domain) -RRType $($wildcardrecord.'Current Wildcard Type') -Name '*'
$AddWildcardScriptBlock
              
"@
            } else {
                Write-Host "Run the following code block to create a Wildcard Record in the $($wildcardrecord.Domain) domain" -ForegroundColor Green
                if ($type -eq '-Txt') {
                    Write-Host "Add-DnsServerResourceRecord -ComputerName $($wildcardrecord.Domain) -ZoneName $($wildcardrecord.Domain) $type -Name '*' -DescriptiveText '0.0.0.0'"
                } elseif ($type -eq '-A') {
                    Write-Host "Add-DnsServerResourceRecord -ComputerName $($wildcardrecord.Domain) -ZoneName $($wildcardrecord.Domain) $type -Name '*' -RecordData '0.0.0.0'"
                }
                Write-Host
            }
        }
    }
}