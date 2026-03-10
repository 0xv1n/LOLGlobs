---
Name: forfiles
Description: "Execute a command for each file matching a wildcard mask. The /m flag accepts glob patterns, and @file expands to the matched filename — enabling indirect execution of binaries."
Platform: windows-cmd
BinaryPath:
  - C:\Windows\System32\forfiles.exe
Category: execution
MitreID: T1059.003
Patterns:
  - Pattern: "forfiles /p C:\\Windows\\System32 /m *.exe /c \"cmd /c @file /?\""
    Wildcards: ["*"]
    Notes: "* mask matches all .exe files; @file expands to each filename"
  - Pattern: "forfiles /m *.bat /c \"cmd /c @file\""
    Wildcards: ["*"]
    Notes: "Execute each .bat file in current directory via cmd"
  - Pattern: "for /f %i in ('where for*.exe') do %i /m *.bat /c \"cmd /c @file\""
    Wildcards: ["*"]
    Notes: "where glob resolves forfiles.exe path; nested * mask in /m for batch files"
  - Pattern: "for /f %i in ('where forf?les.exe') do %i /m *.txt /c \"cmd /c @file\""
    Wildcards: ["?"]
    Notes: "? wildcard in where query for forfiles itself"
  - Pattern: "C:\\Windows\\System32\\FORFIL~1.EXE /m *.bat /c \"cmd /c @file\""
    Wildcards: []
    Notes: "8.3 SFN — FORFIL~1 auto-generated for forfiles.exe; requires NtfsDisable8dot3NameCreation=0"
  - Pattern: "for %i in (C:\\Windows\\System32\\forf*.exe) do @%i /m *.bat /c \"cmd /c @file\""
    Wildcards: ["*"]
    Notes: "Native CMD for loop with filesystem glob — resolves forfiles.exe via forf* expansion; /m *.bat then globs within the current directory"
    Method: "Simple for glob"
  - Pattern: "for /f %i in ('where /r C:\\Windows\\System32 forf*.exe') do %i /m *.bat /c \"cmd /c @file\""
    Wildcards: ["*"]
    Notes: "Recursive where search locates forfiles.exe; nested /m *.bat glob inside forfiles adds a second layer of wildcard resolution"
    Method: "where /r recursive"
PlatformNotes: |
  forfiles is a native CMD utility. Its `/m` flag accepts standard Windows glob wildcards (`*`, `?`). The special variable `@file` expands to the matched filename (quoted), `@path` to the full path, and `@ext` to the extension. This makes forfiles a unique execution primitive that keeps the binary name out of the command line.
Resources:
  - https://attack.mitre.org/techniques/T1059/003/
  - https://lolbas-project.github.io/lolbas/Binaries/Forfiles/
  - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/forfiles
---
