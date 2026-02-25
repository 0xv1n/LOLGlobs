---
Name: Invoke-Command
Description: "Run commands on local or remote computers. Enables lateral movement via PowerShell remoting (WinRM)."
Platform: powershell
BinaryPath:
  - "PowerShell cmdlet"
Category: lateral-movement
MitreID: T1021.006
Patterns:
  - Pattern: "& (gcm I*-C*d) -ComputerName TARGET -ScriptBlock { whoami }"
    Wildcards: ["*"]
    Notes: "Wildcards in verb and noun"
  - Pattern: "& (gcm Invoke-Com*) -ComputerName ..."
    Wildcards: ["*"]
    Notes: "Star matches 'mand'"
  - Pattern: "& (gcm I*ke-Command) -ComputerName ..."
    Wildcards: ["*"]
    Notes: "Wildcard in verb"
  - Pattern: "& (gcm *-Command) -ComputerName ..."
    Wildcards: ["*"]
    Notes: "Prefix wildcard"
  - Pattern: "icm -ComputerName TARGET -ScriptBlock { id }"
    Wildcards: []
    Notes: "Built-in alias 'icm'"
  - Pattern: "& (gcm Invok[d-f]-Command) -ComputerName ..."
    Wildcards: ["[d-f]"]
    Notes: "Character range matches 'e' in Invoke"
  - Pattern: "& (gal ic?) -ComputerName TARGET -ScriptBlock { id }"
    Wildcards: ["?"]
    Notes: "Get-Alias with wildcard resolves 'icm'"
Resources:
  - https://attack.mitre.org/techniques/T1021/006/
  - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/invoke-command
---
