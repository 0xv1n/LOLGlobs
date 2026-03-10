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
  - Pattern: "for %i in (C:\\Windows\\System32\\cm?.exe) do @%i /c whoami"
    Wildcards: ["?"]
    Notes: "Native CMD for loop with filesystem glob — cm? expands to cmd.exe directly in System32"
    Method: "Simple for glob"
  - Pattern: "for /f %i in ('where /r C:\\Windows cm?.exe') do %i /c whoami"
    Wildcards: ["?"]
    Notes: "Recursive where search across Windows tree — finds cmd.exe in System32 and SysWOW64"
    Method: "where /r recursive"
  - Pattern: "set a=cm& set b=d& call %a%%b%.exe /c whoami"
    Wildcards: []
    Notes: "Binary name split across two SET variables — CALL resolves %a%%b%.exe=cmd.exe; name never appears as a literal string"
    Method: "set variable building"
  - Pattern: "cmd /v:on /c \"set x=cmd& !x! /c whoami\""
    Wildcards: []
    Notes: "Delayed variable expansion — /v:on enables !var! syntax; !x! resolves at runtime, evading parse-time static analysis"
    Method: "Delayed expansion"
  - Pattern: "for /f %i in ('where cm?.exe') do start \"\" /b %i /c whoami"
    Wildcards: ["?"]
    Notes: "start /b launches resolved cmd.exe as a background process — changes parent process attribution in event logs"
    Method: "start indirection"
Resources:
  - https://attack.mitre.org/techniques/T1059/003/
  - https://lolbas-project.github.io/lolbas/Binaries/Cmd/
---
