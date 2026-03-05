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
PlatformNotes: |
  `rm`, `del`, and `ri` are built-in aliases. Remove-Item with `-Recurse -Force` silently deletes entire trees. Targets PowerShell providers beyond the filesystem: `Remove-Item HKLM:\SOFTWARE\...` operates on the registry, `Remove-Item Env:\VAR` deletes environment variables.
Resources:
  - https://attack.mitre.org/techniques/T1070/004/
  - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/remove-item
---
