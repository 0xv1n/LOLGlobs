---
Name: Set-Content
Description: "Write content to a file. Used to drop payloads, modify system files, or write scripts to disk for execution."
Platform: powershell
BinaryPath:
  - "PowerShell cmdlet"
Category: execution
MitreID: T1059.001
Patterns:
  - Pattern: "& (gcm S*-C*t) -Path C:\\payload.ps1 -Value $code"
    Wildcards: ["*"]
    Notes: "Wildcards in both verb and noun"
  - Pattern: "& (gcm Set-Con*) -Path ..."
    Wildcards: ["*"]
    Notes: "Star matches 'tent'"
  - Pattern: "& (gcm S?t-Content) -Path ..."
    Wildcards: ["?"]
    Notes: "Single char wildcard replaces 'e'"
  - Pattern: "& (gcm S[d-f]t-Content) -Path ..."
    Wildcards: ["[d-f]"]
    Notes: "Character range matches 'e' in Set"
  - Pattern: "& (gcm *-Content) -Path ..."
    Wildcards: ["*"]
    Notes: "Prefix wildcard — note: also matches Get-Content"
  - Pattern: "sc -Path C:\\file.txt -Value 'data'"
    Wildcards: []
    Notes: "Alias 'sc' (note: conflicts with sc.exe service control)"
Resources:
  - https://attack.mitre.org/techniques/T1059/001/
  - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/set-content
---
