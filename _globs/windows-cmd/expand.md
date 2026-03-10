---
Name: expand
Description: "Expands compressed CAB archive files. Can extract payloads from CAB containers to disk."
Platform: windows-cmd
BinaryPath:
  - C:\Windows\System32\expand.exe
Category: execution
MitreID: T1140
Patterns:
  - Pattern: "for /f %i in ('where exp?nd.exe') do %i payload.cab -F:* C:\\out\\"
    Wildcards: ["?"]
    Notes: "Single char wildcard replaces 'a' — uniquely matches expand.exe without hitting expr.exe"
  - Pattern: "for /f %i in ('where e*nd.exe') do %i payload.cab -F:* C:\\out\\"
    Wildcards: ["*"]
    Notes: "Star matches 'xpa' — resolves to expand.exe (both System32 and Git paths if present)"
  - Pattern: "for /f %i in ('dir /b C:\\Windows\\System32\\exp?nd.exe') do %i payload.cab -F:* C:\\out\\"
    Wildcards: ["?"]
    Notes: "dir /b in System32 with exp?nd.exe — avoids ambiguity with expr.exe or explorer.exe that exp*.exe would match"
  - Pattern: "forfiles /p C:\\Windows\\System32 /m exp?nd.exe /c \"@file payload.cab -F:* C:\\out\\\""
    Wildcards: ["?"]
    Notes: "forfiles ? mask finds expand.exe — @file expands to matched filename"
  - Pattern: "C:\\Windows\\System32\\expand.exe payload.cab -F:* C:\\out\\"
    Wildcards: []
    Notes: "Direct invocation — -F:* extracts all files from the CAB"
  - Pattern: "for %i in (C:\\Windows\\System32\\exp?nd.exe) do @%i payload.cab -F:* C:\\out\\"
    Wildcards: ["?"]
    Notes: "Native CMD for loop with filesystem glob — exp?nd uniquely matches expand.exe without hitting explorer.exe"
    Method: "Simple for glob"
  - Pattern: "for /f %i in ('where /r C:\\Windows\\System32 exp?nd.exe') do %i payload.cab -F:* C:\\out\\"
    Wildcards: ["?"]
    Notes: "Recursive where search — ? wildcard avoids matching explorer.exe or other exp*.exe files"
    Method: "where /r recursive"
PlatformNotes: |
  expand.exe is a built-in Windows utility for extracting CAB files. The `-F:*` flag extracts all files. It is less monitored than certutil for file staging. In batch scripts use `%%i` instead of `%i`.
Resources:
  - https://attack.mitre.org/techniques/T1140/
  - https://lolbas-project.github.io/lolbas/Binaries/Expand/
---
