---
Name: Remove-Item
Description: "Delete files, directories, registry keys, or other PowerShell provider items. Used for log wiping, artifact cleanup, and indicator removal."
Platform: powershell
BinaryPath:
  - "PowerShell cmdlet"
Category: execution
MitreID: T1070.004
Patterns:
  - Pattern: "& (gcm R*-It*) -Path C:\\Windows\\Temp\\* -Recurse -Force"
    Wildcards: ["*"]
    Notes: "Wildcards on both verb and noun"
  - Pattern: "& (gcm Remove-I*) -Path C:\\artifact.log -Force"
    Wildcards: ["*"]
    Notes: "Star suffix matches 'tem'"
  - Pattern: "& (gcm R?move-Item) -Path ..."
    Wildcards: ["?"]
    Notes: "Single char wildcard replaces 'e'"
  - Pattern: "& (gcm *-Item) -Path ..."
    Wildcards: ["*"]
    Notes: "Prefix wildcard — note: may match other *-Item cmdlets; add -CommandType Cmdlet to disambiguate"
  - Pattern: "rm -Path C:\\artifact.log"
    Wildcards: []
    Notes: "Built-in alias 'rm' for Remove-Item"
  - Pattern: "del -Path C:\\artifact.log"
    Wildcards: []
    Notes: "Alias 'del' for Remove-Item"
  - Pattern: "ri -Path C:\\artifact.log"
    Wildcards: []
    Notes: "Alias 'ri' for Remove-Item"
  - Pattern: "& (gal r?) -Path ..."
    Wildcards: ["?"]
    Notes: "Get-Alias r? — resolves 'rm' or 'ri' depending on match; 'ri' is the shorter alias"
  - Pattern: "& (gcm R[d-f]move-Item) -Path C:\\artifact.log -Force"
    Wildcards: ["[d-f]"]
    Notes: "Character range [d-f] matches 'e' in Remove — only character in range that satisfies Remove-Item"
  - Pattern: "& (DIR Alias:/r?) -Path C:\\artifact.log"
    Wildcards: ["?"]
    Notes: "Resolves rm/ri alias via PowerShell's Alias: PSDrive glob — filesystem-style wildcard on the Alias provider"
  - Pattern: "& (gcm * | ? Name -match '^Rem.*It') -Path C:\\artifact.log -Force"
    Wildcards: ["-match"]
    Notes: "Regex -match filter on all commands via Where-Object pipeline — regex alternative to glob wildcards"
  - Pattern: "& (gcm ('{0}move-{1}' -f 'Re','Item')) -Path C:\\artifact.log -Force"
    Wildcards: []
    Notes: "-f format operator constructs 'Remove-Item' from string fragments before gcm resolves it"
    Method: "-f format operator"
PlatformNotes: |
  `rm`, `del`, and `ri` are built-in aliases. Remove-Item with `-Recurse -Force` silently deletes entire trees. Targets PowerShell providers beyond the filesystem: `Remove-Item HKLM:\SOFTWARE\...` operates on the registry, `Remove-Item Env:\VAR` deletes environment variables.
Resources:
  - https://attack.mitre.org/techniques/T1070/004/
  - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/remove-item
---
