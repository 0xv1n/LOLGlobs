---
Name: cmd
Description: "Windows Command Processor. Spawning cmd.exe is a common technique for executing commands, creating shells, and chaining operations."
Platform: windows-cmd
BinaryPath:
  - C:\Windows\System32\cmd.exe
  - C:\Windows\SysWOW64\cmd.exe
Category: execution
MitreID: T1059.003
Patterns:
  - Pattern: "for /f %i in ('where cm?.exe') do %i /c whoami"
    Wildcards: ["?"]
    Notes: "Wildcard replaces 'd' — note: may also match cmp.exe if GNU tools are in PATH; prefer forfiles /p to scope to System32"
  - Pattern: "for /f %i in ('where c*d.exe') do %i"
    Wildcards: ["*"]
    Notes: "Star matches 'm'"
  - Pattern: "for /f %i in ('dir /b C:\\Windows\\System32\\cm?.exe') do %i"
    Wildcards: ["?"]
    Notes: "dir glob search with wildcard"
  - Pattern: "%COMSPEC%"
    Wildcards: []
    Notes: "Environment variable resolves to cmd.exe path — not a glob but a common evasion"
  - Pattern: "for /f %i in ('where cmd*') do %i /c ..."
    Wildcards: ["*"]
    Notes: "Star suffix matches cmd.exe"
  - Pattern: "forfiles /p C:\\Windows\\System32 /m cm?.exe /c \"@file /c whoami\""
    Wildcards: ["?"]
    Notes: "forfiles ? wildcard in /m mask finds cmd.exe — @file expands to matched filename"
  - Pattern: "C:\\WINDOW~1\\System32\\cmd.exe /c whoami"
    Wildcards: []
    Notes: "8.3 SFN for the Windows directory — WINDOW~1 resolves to Windows; requires NtfsDisable8dot3NameCreation=0"
  - Pattern: "%SystemRoot%\\System32\\%COMSPEC:~-7%"
    Wildcards: []
    Notes: "Substring extraction — %COMSPEC% is the full path to cmd.exe; :~-7 extracts last 7 chars ('cmd.exe'), combined with %SystemRoot% to form full path"
Resources:
  - https://attack.mitre.org/techniques/T1059/003/
  - https://lolbas-project.github.io/lolbas/Binaries/Cmd/
---
