---
Name: cscript
Description: "Windows Script Host console runner for JScript and VBScript. Executes script files from disk or UNC paths."
Platform: windows-cmd
BinaryPath:
  - C:\Windows\System32\cscript.exe
  - C:\Windows\SysWOW64\cscript.exe
Category: execution
MitreID: T1059.005
Patterns:
  - Pattern: "for /f %i in ('where cs?ript.exe') do %i script.vbs"
    Wildcards: ["?"]
    Notes: "Single char wildcard replaces 'c' — cs?ript matches cscript"
  - Pattern: "for /f %i in ('where c*ript.exe') do %i script.vbs"
    Wildcards: ["*"]
    Notes: "Star matches 's' after 'c' and before 'ript'"
  - Pattern: "for /f %i in ('where csc*.exe') do %i script.vbs"
    Wildcards: ["*"]
    Notes: "Star suffix matches 'ript.exe'"
  - Pattern: "for /f %i in ('dir /b C:\\Windows\\System32\\csc*.exe') do %i script.vbs"
    Wildcards: ["*"]
    Notes: "dir /b glob finds cscript.exe in System32"
  - Pattern: "forfiles /p C:\\Windows\\System32 /m cs?ript.exe /c \"@file script.vbs\""
    Wildcards: ["?"]
    Notes: "forfiles ? wildcard in mask finds cscript.exe — @file expands to matched filename"
  - Pattern: "C:\\Windows\\System32\\CSCRIP~1.EXE script.vbs"
    Wildcards: []
    Notes: "8.3 SFN — CSCRIP~1 auto-generated for cscript.exe; requires NtfsDisable8dot3NameCreation=0"
  - Pattern: "for %i in (C:\\Windows\\System32\\csc*.exe) do @%i script.vbs"
    Wildcards: ["*"]
    Notes: "Native CMD for loop with filesystem glob — expands csc*.exe directly in System32 without where.exe"
    Method: "Simple for glob"
  - Pattern: "for /f %i in ('where /r C:\\Windows csc*.exe') do %i script.vbs"
    Wildcards: ["*"]
    Notes: "Recursive where search across Windows tree — finds cscript.exe in System32 and SysWOW64"
    Method: "where /r recursive"
  - Pattern: "cmd /v:on /c \"set x=cscript& !x! script.vbs\""
    Wildcards: []
    Notes: "Delayed variable expansion — /v:on enables !var! syntax; !x! resolves at runtime only, invisible to parse-time static analysis"
    Method: "Delayed expansion"
PlatformNotes: |
  cscript.exe runs scripts with console output. wscript.exe is the GUI counterpart. Both are commonly flagged; glob obfuscation on the binary name via `where` or `forfiles` bypasses some string-based detections.
Resources:
  - https://attack.mitre.org/techniques/T1059/005/
  - https://lolbas-project.github.io/lolbas/Binaries/Cscript/
---
