---
Name: Start-Process
Description: "Start one or more processes. Can launch executables with specific arguments, working directories, and window styles."
Platform: powershell
BinaryPath:
  - "PowerShell cmdlet"
Category: execution
MitreID: T1059.001
Patterns:
  - Pattern: "& (gcm S*a*-P*ess) -FilePath cmd.exe"
    Wildcards: ["*"]
    Notes: "Wildcards in verb and noun"
  - Pattern: "& (gcm Start-Pro*) -FilePath ..."
    Wildcards: ["*"]
    Notes: "Star matches 'cess'"
  - Pattern: "& (gcm S?art-Process) -FilePath ..."
    Wildcards: ["?"]
    Notes: "Single char wildcard replaces 't'"
  - Pattern: "& (gcm S[s-u]art-Process) -FilePath ..."
    Wildcards: ["[s-u]"]
    Notes: "Character range matches 't' in Start"
  - Pattern: "& (gcm *-Process) -FilePath ..."
    Wildcards: ["*"]
    Notes: "Prefix wildcard"
  - Pattern: "saps -FilePath cmd.exe"
    Wildcards: []
    Notes: "Built-in alias 'saps' for Start-Process"
  - Pattern: "start cmd.exe"
    Wildcards: []
    Notes: "Alias 'start' for Start-Process"
  - Pattern: "& (gal sa?s) cmd.exe"
    Wildcards: ["?"]
    Notes: "Get-Alias with wildcard resolves 'saps' — sa?s avoids matching 'spps' (Stop-Process)"
  - Pattern: "& (gcm *rocess) cmd.exe"
    Wildcards: ["*"]
    Notes: "Short suffix pattern"
  - Pattern: "& (gcm Start-Pro*) (Resolve-Path C:\\Win*\\Sys*32\\cmd.exe)"
    Wildcards: ["*"]
    Notes: "Double glob — gcm wildcard resolves Start-Process AND Resolve-Path filesystem glob resolves the binary path to cmd.exe"
  - Pattern: "& (DIR Alias:/sa?s) cmd.exe"
    Wildcards: ["?"]
    Notes: "Resolves saps alias via PowerShell's Alias: PSDrive glob — sa?s matches saps (Start-Process)"
  - Pattern: "& (gcm * | ? Name -match '^St.*Pro') -FilePath cmd.exe"
    Wildcards: ["-match"]
    Notes: "Regex -match filter on all commands via Where-Object pipeline — regex alternative to glob wildcards"
  - Pattern: "& (gcm ('{0}-{1}' -f 'Start','Process')) -FilePath cmd.exe"
    Wildcards: []
    Notes: "-f format operator constructs 'Start-Process' from string fragments before gcm resolves it"
    Method: "-f format operator"
  - Pattern: "& (Get-Command -Verb Start* -Noun *Process) -FilePath cmd.exe"
    Wildcards: ["*"]
    Notes: "Get-Command -Verb/-Noun structured split — wildcards on verb and noun independently narrow the match to Start-Process"
    Method: "Get-Command -Verb -Noun"
  - Pattern: "& ($ExecutionContext.InvokeCommand.GetCommand('Start-Pro*','Cmdlet')) -FilePath cmd.exe"
    Wildcards: ["*"]
    Notes: "Engine-level cmdlet resolution via InvokeCommand.GetCommand — bypasses Get-Command entirely; Start-Pro* resolves to Start-Process"
    Method: "ExecutionContext resolution"
  - Pattern: "& (gcm ('Start'+'-Pro'+'cess')) -FilePath cmd.exe"
    Wildcards: []
    Notes: "String concatenation builds the cmdlet name from three fragments — full name never appears contiguous in source"
    Method: "String concatenation"
  - Pattern: "$c = gcm Start-Pro*; & $c -FilePath cmd.exe"
    Wildcards: ["*"]
    Notes: "Variable-based invocation — glob resolves to Start-Process at assignment time; & invokes the stored CommandInfo object"
    Method: "Variable invocation"
Resources:
  - https://attack.mitre.org/techniques/T1059/001/
  - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/start-process
---
