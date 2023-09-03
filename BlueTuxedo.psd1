@{
    AliasesToExport      = @('*')
    Author               = 'Jake Hildreth and Jim Sykora'
    CmdletsToExport      = @()
    CompatiblePSEditions = @('Desktop', 'Core')
    Copyright            = '(c) 2022 - 2023. All rights reserved.'
    Description          = 'A tiny tool to identify and remediate common misconfigurations in Active Directory-Integrated DNS.'
    FunctionsToExport    = @('*')
    GUID                 = 'e98445b3-1d76-4a51-831d-ddfc7e0213fa'
    ModuleVersion        = '2023.10'
    PowerShellVersion    = '5.1'
    PrivateData          = @{
        PSData = @{
            ExternalModuleDependencies = @('ActiveDirectory', 'ServerManager', 'Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.LocalAccounts', 'Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.Management', 'CimCmdlets', 'Dism')
            Tags                       = @('Windows', 'BlueTuxedo', 'DNS', 'AD', 'ActiveDirectory', 'DomainNameSystem', 'ADIDNS')
        }
    }
    RequiredModules      = @('ActiveDirectory', 'ServerManager', 'Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.LocalAccounts', 'Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.Management', 'CimCmdlets', 'Dism')
    RootModule           = 'BlueTuxedo.psm1'
}