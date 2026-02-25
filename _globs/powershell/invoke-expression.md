---
Name: Invoke-Expression
Description: "Execute arbitrary strings as PowerShell commands. The most direct code execution primitive — equivalent to eval()."
Platform: powershell
BinaryPath:
  - "PowerShell cmdlet"
Category: execution
MitreID: T1059.001
Patterns:
  - Pattern: "& (gcm I*ke-E*) 'Get-Process'"
    Wildcards: ["*"]
    Notes: "Wildcards in both verb and noun"
  - Pattern: "& (gal i?x) 'whoami'"
    Wildcards: ["?"]
    Notes: "Get-Alias (gal) with wildcard — 'iex' is the alias for Invoke-Expression"
  - Pattern: "& (gal ?e?) 'whoami'"
    Wildcards: ["?"]
    Notes: "Wildcards around 'e' in 'iex' alias"
  - Pattern: "iex 'whoami'"
    Wildcards: []
    Notes: "Direct alias use — not a glob but the canonical short form"
  - Pattern: "& (gcm *xpression) 'payload'"
    Wildcards: ["*"]
    Notes: "Wildcard prefix matches 'Invoke-E'"
  - Pattern: "& (gcm Invoke-Ex*) 'payload'"
    Wildcards: ["*"]
    Notes: "Wildcard suffix matches 'pression'"
  - Pattern: "& (Get-Alias i?x) 'payload'"
    Wildcards: ["?"]
    Notes: "Full Get-Alias with wildcard"
  - Pattern: "& (gcm Invok[d-f]-Expression) 'payload'"
    Wildcards: ["[d-f]"]
    Notes: "Character range matches 'e' in Invoke"
PlatformNotes: |
  `iex` is a built-in alias. `Invoke-Expression` is one of the most monitored cmdlets. Wildcards on the cmdlet name via `gcm` or `gal` can bypass signature-based detections. Also works with base64: `iex ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('...')))`.
Resources:
  - https://attack.mitre.org/techniques/T1059/001/
  - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-expression
---
