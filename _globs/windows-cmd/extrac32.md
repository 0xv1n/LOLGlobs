---
Name: extrac32
Description: "CAB extraction utility bundled with Internet Explorer. Less monitored than expand.exe, can extract payloads from CAB archives."
Platform: windows-cmd
BinaryPath:
  - C:\Windows\System32\extrac32.exe
Category: execution
MitreID: T1218
Patterns:
  - Pattern: "for /f %i in ('where ext*32.exe') do %i /e /y payload.cab C:\\out\\"
    Wildcards: ["*"]
    Notes: "Star matches 'rac' between 'ext' and '32'"
  - Pattern: "for /f %i in ('where extrac*.exe') do %i /e /y payload.cab C:\\out\\"
    Wildcards: ["*"]
    Notes: "Star suffix matches '32.exe'"
  - Pattern: "for /f %i in ('where ext?ac32.exe') do %i /e /y payload.cab C:\\out\\"
    Wildcards: ["?"]
    Notes: "Single char wildcard replaces 'r'"
  - Pattern: "for /f %i in ('dir /b C:\\Windows\\System32\\extrac*.exe') do %i /e payload.cab C:\\out\\"
    Wildcards: ["*"]
    Notes: "dir /b glob finds extrac32.exe in System32"
  - Pattern: "forfiles /p C:\\Windows\\System32 /m ext*32.exe /c \"@file /e payload.cab C:\\out\\\""
    Wildcards: ["*"]
    Notes: "forfiles * mask finds extrac32.exe — @file expands to matched filename"
  - Pattern: "C:\\Windows\\System32\\EXTRAC~1.EXE /e /y payload.cab C:\\out\\"
    Wildcards: []
    Notes: "8.3 SFN — EXTRAC~1 auto-generated for extrac32.exe; requires NtfsDisable8dot3NameCreation=0"
PlatformNotes: |
  extrac32.exe is a legacy CAB extraction utility. The `/e` flag extracts all files. It is often overlooked in EDR rule sets compared to certutil or expand. In batch scripts use `%%i` instead of `%i`.
Resources:
  - https://attack.mitre.org/techniques/T1218/
  - https://lolbas-project.github.io/lolbas/Binaries/Extrac32/
---
