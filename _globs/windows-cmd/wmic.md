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
  - Pattern: "for %i in (C:\\Windows\\System32\\wbem\\wmi?.exe) do @%i process call create cmd.exe"
    Wildcards: ["?"]
    Notes: "Native CMD for loop with filesystem glob — wmi? uniquely matches wmic.exe in the wbem subdirectory"
    Method: "Simple for glob"
  - Pattern: "for /f %i in ('where /r C:\\Windows\\System32\\wbem wmi?.exe') do %i process call create cmd.exe"
    Wildcards: ["?"]
    Notes: "Recursive where search scoped to wbem directory — wmic.exe lives in System32\\wbem, not directly in System32"
    Method: "where /r recursive"
  - Pattern: "forfiles /p C:\\Windows\\System32\\wbem /m wmi?.exe /c \"@file process call create cmd.exe\""
    Wildcards: ["?"]
    Notes: "forfiles ? mask scoped to the wbem subdirectory where wmic.exe resides — @file expands to matched filename"
  - Pattern: "cmd /c for /f %i in ('where wmi?.exe') do %i process call create cmd.exe"
    Wildcards: ["?"]
    Notes: "cmd /c wrapper adds an extra process layer — glob resolves via where; parent process becomes cmd.exe not the caller"
    Method: "cmd /c indirection"
Resources:
  - https://attack.mitre.org/techniques/T1047/
  - https://lolbas-project.github.io/lolbas/Binaries/Wmic/
---
