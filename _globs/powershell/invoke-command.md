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
  - Pattern: "& (DIR Alias:/ic?) -ComputerName TARGET -ScriptBlock { whoami }"
    Wildcards: ["?"]
    Notes: "Resolves icm alias via PowerShell's Alias: PSDrive glob — ic? matches icm (Invoke-Command)"
  - Pattern: "& (gcm ('{0}voke-{1}' -f 'In','Command')) -ComputerName TARGET -ScriptBlock { whoami }"
    Wildcards: []
    Notes: "-f format operator constructs 'Invoke-Command' from string fragments before gcm resolves it"
    Method: "-f format operator"
  - Pattern: "& (Get-Command -Verb Inv* -Noun *Command) -ComputerName TARGET -ScriptBlock { whoami }"
    Wildcards: ["*"]
    Notes: "Get-Command -Verb/-Noun structured split — wildcards on verb and noun independently narrow the match to Invoke-Command"
    Method: "Get-Command -Verb -Noun"
  - Pattern: "& (gcm `I`n`v`o`k`e-Command) -ComputerName TARGET -ScriptBlock { whoami }"
    Wildcards: []
    Notes: "Backtick character insertion — PowerShell ignores backticks before most characters, so the name resolves normally but string-matching signatures miss it"
    Method: "Backtick insertion"
Resources:
  - https://attack.mitre.org/techniques/T1021/006/
  - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/invoke-command
---
