---
Name: powershell.exe
Description: "PowerShell executable launched from CMD. Bypasses CMD-level restrictions by delegating to PowerShell runtime."
Platform: windows-cmd
BinaryPath:
  - C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  - C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe
Category: execution
MitreID: T1059.001
Patterns:
  - Pattern: "for /f %i in ('where powers*') do %i -nop -w hidden -c IEX(...)"
    Wildcards: ["*"]
    Notes: "Star matches 'hell.exe'"
  - Pattern: "for /f %i in ('where power?hell.exe') do %i"
    Wildcards: ["?"]
    Notes: "Wildcard replaces 's'"
  - Pattern: "for /f %i in ('where p*hell.exe') do %i"
    Wildcards: ["*"]
    Notes: "Star matches 'owers'"
  - Pattern: "for /f %i in ('dir /b C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\power*.exe') do %i"
    Wildcards: ["*"]
    Notes: "Full path dir glob"
  - Pattern: "forfiles /p C:\\Windows\\System32\\WindowsPowerShell\\v1.0 /m power*.exe /c \"@file -nop -c whoami\""
    Wildcards: ["*"]
    Notes: "forfiles * mask finds powershell.exe in its install directory — @file expands to matched filename"
  - Pattern: "C:\\Windows\\System32\\WINDOW~1\\v1.0\\POWERS~1.EXE -nop -c whoami"
    Wildcards: []
    Notes: "8.3 SFN — WINDOW~1 for WindowsPowerShell, POWERS~1 for powershell.exe; requires NtfsDisable8dot3NameCreation=0"
  - Pattern: "for %i in (C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\power*.exe) do @%i -nop -c whoami"
    Wildcards: ["*"]
    Notes: "Native CMD for loop with filesystem glob — expands power*.exe in the PowerShell install directory"
    Method: "Simple for glob"
  - Pattern: "for /f %i in ('where /r C:\\Windows power?hell.exe') do %i -nop -c whoami"
    Wildcards: ["?"]
    Notes: "Recursive where search across Windows tree — finds powershell.exe in WindowsPowerShell subdirectory without spelling the full path"
    Method: "where /r recursive"
  - Pattern: "set a=powers& set b=hell& call %a%%b%.exe -nop -c whoami"
    Wildcards: []
    Notes: "Binary name split across two SET variables — CALL resolves %a%%b%.exe=powershell.exe; name never appears as a literal string"
    Method: "set variable building"
  - Pattern: "for /f %i in ('where power?hell.exe') do start \"\" /b %i -nop -c whoami"
    Wildcards: ["?"]
    Notes: "start /b launches powershell.exe as a detached background process — changes parent process attribution in event logs"
    Method: "start indirection"
Resources:
  - https://attack.mitre.org/techniques/T1059/001/
  - https://lolbas-project.github.io/lolbas/Binaries/Powershell/
---
