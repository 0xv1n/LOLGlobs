---
Name: Add-Type
Description: "Compile and load C# or other .NET language code at runtime. Enables direct Windows API access and arbitrary .NET code execution without touching disk."
Platform: powershell
BinaryPath:
  - "PowerShell cmdlet"
Category: execution
MitreID: T1059.001
Patterns:
  - Pattern: "& (gcm A*-T*) -TypeDefinition 'public class C { ... }'"
    Wildcards: ["*"]
    Notes: "Wildcards on both verb and noun"
  - Pattern: "& (gcm Add-Ty*) -TypeDefinition ..."
    Wildcards: ["*"]
    Notes: "Star suffix matches 'pe'"
  - Pattern: "& (gcm A?d-Type) -TypeDefinition ..."
    Wildcards: ["?"]
    Notes: "Single char wildcard replaces 'd'"
  - Pattern: "& (gcm *-Type) -TypeDefinition ..."
    Wildcards: ["*"]
    Notes: "Prefix wildcard — use -CommandType Cmdlet to limit results"

  - Pattern: "& (gcm A*-T*) -MemberDefinition '[DllImport(\"kernel32.dll\")] public static extern ...' -Name Win32 -Namespace API"
    Wildcards: ["*"]
    Notes: "-MemberDefinition form for P/Invoke — inline DllImport without a full class definition"
  - Pattern: "& (gcm A[c-e]d-Type) -TypeDefinition 'public class C { ... }'"
    Wildcards: ["[c-e]"]
    Notes: "Character range [c-e] matches 'd' in Add — only character in range that satisfies Add-Type"
  - Pattern: "& ($ExecutionContext.InvokeCommand.GetCommand('A*-Type','Cmdlet')) -TypeDefinition 'public class C { ... }'"
    Wildcards: ["*"]
    Notes: "Engine-level cmdlet resolution via InvokeCommand.GetCommand — bypasses Get-Command entirely; A*-Type resolves to Add-Type"
    Method: "ExecutionContext resolution"
  - Pattern: "& (gcm ('{0}dd-{1}' -f 'A','Type')) -TypeDefinition 'public class C { ... }'"
    Wildcards: []
    Notes: "-f format operator constructs the cmdlet name 'Add-Type' from string fragments before gcm resolves it"
    Method: "-f format operator"
PlatformNotes: |
  Add-Type compiles C# code in memory (using the .NET compiler) and loads the resulting assembly into the PowerShell session. It enables P/Invoke for Windows API calls: `Add-Type -MemberDefinition '[DllImport("kernel32.dll")] ...' -Name Win32 -Namespace API`. No files are written to disk by default when using `-TypeDefinition` or `-MemberDefinition`.
Resources:
  - https://attack.mitre.org/techniques/T1059/001/
  - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/add-type
---
