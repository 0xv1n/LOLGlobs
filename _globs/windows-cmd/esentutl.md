---
Name: esentutl
Description: "Extensible Storage Engine utility. Can copy locked or in-use files (e.g., NTDS.dit, SAM) and is used for credential access and file staging."
Platform: windows-cmd
BinaryPath:
  - C:\Windows\System32\esentutl.exe
Category: download
MitreID: T1105
Patterns:
  - Pattern: "for /f %i in ('where esen*.exe') do %i /y source.edb destination.edb"
    Wildcards: ["*"]
    Notes: "Star matches 'tutl' after 'esen'"
  - Pattern: "for /f %i in ('where esentut?.exe') do %i /y source.edb dest.edb"
    Wildcards: ["?"]
    Notes: "Single char wildcard replaces 'l'"
  - Pattern: "for /f %i in ('where e*tl.exe') do %i /y source.edb dest.edb"
    Wildcards: ["*"]
    Notes: "Star matches 'sen' + 'tu' between 'e' and 'tl'"
  - Pattern: "for /f %i in ('dir /b C:\\Windows\\System32\\esen*.exe') do %i /y src dest"
    Wildcards: ["*"]
    Notes: "dir /b glob finds esentutl.exe in System32"
  - Pattern: "forfiles /p C:\\Windows\\System32 /m esen*.exe /c \"@file /y source dest\""
    Wildcards: ["*"]
    Notes: "forfiles * mask finds esentutl.exe — @file expands to matched filename"
PlatformNotes: |
  esentutl.exe can copy files that are locked by the OS (using VSS or direct ESE access). This makes it useful for extracting credential stores like `NTDS.dit` or the SAM hive. The `/y` flag copies a file, `/vss` accesses via Volume Shadow Copy. In batch scripts use `%%i` instead of `%i`.
Resources:
  - https://attack.mitre.org/techniques/T1105/
  - https://lolbas-project.github.io/lolbas/Binaries/Esentutl/
---
