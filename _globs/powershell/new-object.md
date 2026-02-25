---
Name: New-Object
Description: "Creates .NET or COM objects. Used to instantiate WebClient for downloads, create COM shells, or access Windows APIs."
Platform: powershell
BinaryPath:
  - "PowerShell cmdlet"
Category: download
MitreID: T1105
Patterns:
  - Pattern: "& (gcm N*-O*) System.Net.WebClient"
    Wildcards: ["*"]
    Notes: "Wildcards on both verb and noun"
  - Pattern: "& (gcm New-Ob*) System.Net.WebClient"
    Wildcards: ["*"]
    Notes: "Star matches 'ject'"
  - Pattern: "& (gcm N?w-Object) System.Net.WebClient"
    Wildcards: ["?"]
    Notes: "Single char wildcard replaces 'e'"
  - Pattern: "& (gcm N[d-f]w-Object) System.Net.WebClient"
    Wildcards: ["[d-f]"]
    Notes: "Character range matches 'e' in New"
  - Pattern: "(& (gcm N*-O*) Net.WebClient).DownloadFile('http://...','C:\\p.exe')"
    Wildcards: ["*"]
    Notes: "Full download one-liner with glob-resolved cmdlet"
  - Pattern: "& (gcm *Object) Net.WebClient"
    Wildcards: ["*"]
    Notes: "Prefix wildcard"
Resources:
  - https://attack.mitre.org/techniques/T1105/
  - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/new-object
---
