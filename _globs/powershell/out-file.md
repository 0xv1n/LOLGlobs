---
Name: Out-File
Description: "Send pipeline output to a file. Alternative to Set-Content with pipeline support — used to write payloads, scripts, or exfiltrated data to disk."
Platform: powershell
BinaryPath:
  - "PowerShell cmdlet"
Category: execution
MitreID: T1059.001
Patterns:
  - Pattern: "& (gcm O*-F*) -FilePath C:\\out.txt"
    Wildcards: ["*"]
    Notes: "Wildcards on both verb and noun"
  - Pattern: "& (gcm Out-Fil*) -FilePath C:\\out.txt"
    Wildcards: ["*"]
    Notes: "Star suffix matches 'e'"
  - Pattern: "& (gcm O?t-File) -FilePath C:\\out.txt"
    Wildcards: ["?"]
    Notes: "Single char wildcard replaces 'u'"
  - Pattern: "& (gcm *-File) -FilePath C:\\out.txt"
    Wildcards: ["*"]
    Notes: "Prefix wildcard — add -CommandType Cmdlet to avoid matching aliases"
  - Pattern: "'payload' | & (gcm O*-F*) -FilePath C:\\payload.ps1"
    Wildcards: ["*"]
    Notes: "Pipeline form — writes string to file via glob-resolved Out-File"
PlatformNotes: |
  Out-File writes pipeline output to a file. Key differences from Set-Content: accepts pipeline input directly, uses the console encoding by default, and supports `-Append`. The `-Encoding` parameter controls output encoding. Useful for writing scripts to disk: `'IEX ...' | Out-File payload.ps1`.
Resources:
  - https://attack.mitre.org/techniques/T1059/001/
  - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/out-file
---
