---
Name: Get-Content
Description: "Read file contents. Equivalent to cat on Linux. Used to read sensitive files, credentials, and configuration data."
Platform: powershell
BinaryPath:
  - "PowerShell cmdlet"
Category: discovery
MitreID: T1005
Patterns:
  - Pattern: "& (gcm G*-C*t) C:\\Windows\\System32\\drivers\\etc\\hosts"
    Wildcards: ["*"]
    Notes: "Wildcards in both verb and noun"
  - Pattern: "& (gcm Get-Con*) ..."
    Wildcards: ["*"]
    Notes: "Star matches 'tent'"
  - Pattern: "& (gcm G?t-Content) ..."
    Wildcards: ["?"]
    Notes: "Single char wildcard replaces 'e'"
  - Pattern: "& (gcm G[d-f]t-Content) ..."
    Wildcards: ["[d-f]"]
    Notes: "Character range matches 'e' in Get"
  - Pattern: "gc C:\\sensitive\\file.txt"
    Wildcards: []
    Notes: "Built-in alias 'gc' for Get-Content"
  - Pattern: "cat C:\\sensitive\\file.txt"
    Wildcards: []
    Notes: "Alias 'cat' also works in PowerShell"
  - Pattern: "type C:\\sensitive\\file.txt"
    Wildcards: []
    Notes: "Alias 'type' also resolves to Get-Content"
  - Pattern: "& (gcm *Content) ..."
    Wildcards: ["*"]
    Notes: "Prefix wildcard"
Resources:
  - https://attack.mitre.org/techniques/T1005/
  - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-content
---
