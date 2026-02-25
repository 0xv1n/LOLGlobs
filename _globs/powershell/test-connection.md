---
Name: Test-Connection
Description: "Send ICMP echo requests (ping). Used for host discovery and network reconnaissance within PowerShell scripts."
Platform: powershell
BinaryPath:
  - "PowerShell cmdlet"
Category: reconnaissance
MitreID: T1018
Patterns:
  - Pattern: "& (gcm T*-C*n) -ComputerName 192.168.1.1"
    Wildcards: ["*"]
    Notes: "Wildcards in both verb and noun"
  - Pattern: "& (gcm Test-Con*) -ComputerName ..."
    Wildcards: ["*"]
    Notes: "Star matches 'nection'"
  - Pattern: "& (gcm T?st-Connection) -ComputerName ..."
    Wildcards: ["?"]
    Notes: "Single char wildcard replaces 'e'"
  - Pattern: "& (gcm T[d-f]st-Connection) -ComputerName ..."
    Wildcards: ["[d-f]"]
    Notes: "Character range matches 'e' in Test"
  - Pattern: "& (gcm *Connection) -ComputerName ..."
    Wildcards: ["*"]
    Notes: "Prefix wildcard"
Resources:
  - https://attack.mitre.org/techniques/T1018/
  - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/test-connection
---
