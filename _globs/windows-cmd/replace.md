---
Name: replace
Description: "Replaces (copies) files from a source to a destination directory. Can be used to stage payloads by copying files into target directories."
Platform: windows-cmd
BinaryPath:
  - C:\Windows\System32\replace.exe
Category: execution
MitreID: T1105
Patterns:
  - Pattern: "for /f %i in ('where replac*.exe') do %i C:\\source\\payload.exe C:\\dest\\"
    Wildcards: ["*"]
    Notes: "replac* uniquely matches replace.exe — rep*.exe is too broad (also hits repair-bde.exe)"
  - Pattern: "for /f %i in ('where r?place.exe') do %i C:\\source\\payload.exe C:\\dest\\"
    Wildcards: ["?"]
    Notes: "Single char wildcard replaces 'e'"
  - Pattern: "for /f %i in ('where replac?.exe') do %i C:\\source\\payload.exe C:\\dest\\"
    Wildcards: ["?"]
    Notes: "Single char wildcard replaces last char 'e'"
  - Pattern: "for /f %i in ('dir /b C:\\Windows\\System32\\replac*.exe') do %i C:\\src\\p.exe C:\\dst\\"
    Wildcards: ["*"]
    Notes: "dir /b in System32 with replac* — avoids also matching repair-bde.exe"
  - Pattern: "forfiles /p C:\\Windows\\System32 /m replac*.exe /c \"@file C:\\source\\p.exe C:\\dest\\\""
    Wildcards: ["*"]
    Notes: "forfiles replac* mask uniquely matches replace.exe in System32"
  - Pattern: "C:\\Windows\\System32\\replace.exe C:\\source\\payload.exe C:\\dest\\ /a"
    Wildcards: []
    Notes: "Direct invocation — /a adds files that don't already exist in destination"
PlatformNotes: |
  replace.exe copies files from a source to a destination directory (not filename-to-filename). The `/a` flag adds files that are not already present. It is rarely monitored as a file-transfer utility. In batch scripts use `%%i` instead of `%i`.
Resources:
  - https://attack.mitre.org/techniques/T1105/
  - https://lolbas-project.github.io/lolbas/Binaries/Replace/
---
