---
Name: wscript
Description: "Windows Script Host GUI runner for JScript and VBScript. Executes scripts without a visible console window."
Platform: windows-cmd
BinaryPath:
  - C:\Windows\System32\wscript.exe
  - C:\Windows\SysWOW64\wscript.exe
Category: execution
MitreID: T1059.005
Patterns:
  - Pattern: "for /f %i in ('where ws?ript.exe') do %i script.vbs"
    Wildcards: ["?"]
    Notes: "Single char wildcard replaces 'c'"
  - Pattern: "for /f %i in ('where w*ript.exe') do %i script.vbs"
    Wildcards: ["*"]
    Notes: "Star matches 'sc' after 'w'"
  - Pattern: "for /f %i in ('where wsc*.exe') do %i script.vbs"
    Wildcards: ["*"]
    Notes: "Star suffix matches 'ript.exe'"
  - Pattern: "for /f %i in ('dir /b C:\\Windows\\System32\\wsc*.exe') do %i script.vbs"
    Wildcards: ["*"]
    Notes: "dir /b glob finds wscript.exe in System32"
  - Pattern: "forfiles /p C:\\Windows\\System32 /m ws?ript.exe /c \"@file script.vbs\""
    Wildcards: ["?"]
    Notes: "forfiles ? mask finds wscript.exe — @file expands to matched filename"
  - Pattern: "C:\\Windows\\System32\\WSCRIP~1.EXE script.vbs"
    Wildcards: []
    Notes: "8.3 SFN — WSCRIP~1 auto-generated for wscript.exe; requires NtfsDisable8dot3NameCreation=0"
PlatformNotes: |
  wscript.exe runs scripts silently (no console window), making it useful for stealthy execution. cscript.exe is the console counterpart. Both share the Windows Script Host engine and accept the same script formats.
Resources:
  - https://attack.mitre.org/techniques/T1059/005/
  - https://lolbas-project.github.io/lolbas/Binaries/Wscript/
---
