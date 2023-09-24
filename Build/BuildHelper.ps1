Get-Module BlueTuxedo | Remove-Module
.\Build\Build-Module.ps1
Import-Module .\BlueTuxedo.psd1
Invoke-BlueTuxedo