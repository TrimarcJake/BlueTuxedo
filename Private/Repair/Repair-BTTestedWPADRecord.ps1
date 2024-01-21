function Repair-BTTestedWPADRecord {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]$TestedWPADRecords,
        [switch]$Run = $false
    )

    if ($null -eq $TestedWPADRecords) {
        $TestedWPADRecords = Test-BTTestedWPADRecord
    }

    if ($Run) {
        foreach ($wpadrecord in $TestedWPADRecords) {
            $type = "-$($wpadrecord.'Correct Type')"
            if ($wpadrecord.'WPAD Exists?') {
                Remove-DnsServerResourceRecord -ComputerName $wpadrecord.Domain -ZoneName $wpadrecord.Domain -RRType $wpadrecord.'Current WPAD Type' -Name 'WPAD'
            }
            if ($type -eq '-Txt') {
                $AddWPADScriptBlock = "Add-DnsServerResourceRecord -ComputerName $($wpadrecord.Domain) -ZoneName $($wpadrecord.Domain) $type -Name 'WPAD' -DescriptiveText '0.0.0.0'"
            } elseif ($type -eq '-A') {
                $AddWPADScriptBlock = "Add-DnsServerResourceRecord -ComputerName $($wpadrecord.Domain) -ZoneName $($wpadrecord.Domain) $type -Name 'WPAD' -RecordData '0.0.0.0'"
            }
            $ScriptBlock = [scriptblock]::Create($AddWPADScriptBlock)
            Invoke-Command -ScriptBlock $ScriptBlock
        }
    } else {
        foreach ($wpadrecord in $TestedWPADRecords) {
            $type = "-$($wpadrecord.'Correct Type')"
            if ($wpadrecord.'WPAD Exists?') {
                Write-Host "Run the following code block to delete the WPAD Record of incorrect type ($($wpadrecord.'Current WPAD Type')) and replace with a WPAD Record of the correct type ($type) in the $($wpadrecord.Domain) domain" -ForegroundColor Green
                if ($type -eq '-Txt') {
                    $AddWPADScriptBlock = "Add-DnsServerResourceRecord -ComputerName $($wpadrecord.Domain) -ZoneName $($wpadrecord.Domain) $type -Name 'WPAD' -DescriptiveText '0.0.0.0'"
                } elseif ($type -eq '-A') {
                    $AddWPADScriptBlock = "Add-DnsServerResourceRecord -ComputerName $($wpadrecord.Domain) -ZoneName $($wpadrecord.Domain) $type -Name 'WPAD' -RecordData '0.0.0.0'"
                }
                Write-Host @"
Remove-DnsServerResourceRecord -ComputerName $($wpadrecord.Domain) -ZoneName $($wpadrecord.Domain) -RRType $($wpadrecord.'Current WPAD Type') -Name 'WPAD'
$AddWPADScriptBlock
              
"@
            } else {
                Write-Host "Run the following code block to create a WPAD Record in the $($wpadrecord.Domain) domain" -ForegroundColor Green
                if ($type -eq '-Txt') {
                    Write-Host "Add-DnsServerResourceRecord -ComputerName $($wpadrecord.Domain) -ZoneName $($wpadrecord.Domain) $type -Name 'WPAD' -DescriptiveText '0.0.0.0'"
                } elseif ($type -eq '-A') {
                    Write-Host "Add-DnsServerResourceRecord -ComputerName $($wpadrecord.Domain) -ZoneName $($wpadrecord.Domain) $type -Name 'WPAD' -RecordData '0.0.0.0'"
                }
                Write-Host
            }
        }
    }
}