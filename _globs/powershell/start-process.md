---
Name: Start-Process
Description: "Start one or more processes. Can launch executables with specific arguments, working directories, and window styles."
Platform: powershell
BinaryPath:
  - "PowerShell cmdlet"
Category: execution
MitreID: T1059.001
Patterns:
  - Pattern: "& (gcm S*a*-P*ess) -FilePath cmd.exe"
    Wildcards: ["*"]
    Notes: "Wildcards in verb and noun"
  - Pattern: "& (gcm Start-Pro*) -FilePath ..."
    Wildcards: ["*"]
    Notes: "Star matches 'cess'"
  - Pattern: "& (gcm S?art-Process) -FilePath ..."
    Wildcards: ["?"]
    Notes: "Single char wildcard replaces 't'"
  - Pattern: "& (gcm *-Process) -FilePath ..."
    Wildcards: ["*"]
    Notes: "Prefix wildcard"
  - Pattern: "saps -FilePath cmd.exe"
    Wildcards: []
    Notes: "Built-in alias 'saps' for Start-Process"
  - Pattern: "& (gcm *rocess) cmd.exe"
    Wildcards: ["*"]
    Notes: "Short suffix pattern"
Resources:
  - https://attack.mitre.org/techniques/T1059/001/
  - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/start-process
---
