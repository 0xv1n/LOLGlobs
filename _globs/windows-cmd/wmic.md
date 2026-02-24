---
Name: wmic
Description: "WMI command-line interface. Used for system information gathering, remote execution, process creation, and persistence."
Platform: windows-cmd
BinaryPath:
  - C:\Windows\System32\wbem\wmic.exe
Category: execution
MitreID: T1047
Patterns:
  - Pattern: "for /f %i in ('where wmi?.exe') do %i process call create cmd.exe"
    Wildcards: ["?"]
    Notes: "Wildcard replaces 'c'"
  - Pattern: "for /f %i in ('where wmi*c.exe') do %i"
    Wildcards: ["*"]
    Notes: "Star intentionally matches nothing (or variant chars); more specific than w*c.exe to avoid ambiguity with windmc.exe"
  - Pattern: "for /f %i in ('dir /b C:\\Windows\\System32\\wbem\\wmi?.exe') do %i"
    Wildcards: ["?"]
    Notes: "Full path dir glob"
  - Pattern: "for /f %i in ('where wmic*') do %i"
    Wildcards: ["*"]
    Notes: "Trailing star matches '.exe'"
Resources:
  - https://attack.mitre.org/techniques/T1047/
  - https://lolbas-project.github.io/lolbas/Binaries/Wmic/
---
