---
Name: dd
Description: "Convert and copy files or block devices. Used for disk imaging, raw data exfiltration, and overwriting disk regions."
Platform: linux
BinaryPath:
  - /bin/dd
  - /usr/bin/dd
Category: exfiltration
MitreID: T1005
Patterns:
  - Pattern: "d?"
    Wildcards: ["?"]
    Notes: "Single wildcard — very short command name; may match df/du/dh depending on PATH (use full path to avoid ambiguity)"
  - Pattern: "/bin/d?"
    Wildcards: ["?"]
    Notes: "Full path with wildcard on last char — more specific than bare d?"
  - Pattern: "/???/d?"
    Wildcards: ["?"]
    Notes: "Both path component and command name obfuscated with ?"
  - Pattern: "$(ls /bin/dd)"
    Wildcards: []
    Notes: "Command substitution via ls — obfuscates the path; dd is too short to use ? glob uniquely"
  - Pattern: "$'\\x64\\x64'"
    Wildcards: []
    Notes: "ANSI-C hex escapes expand to 'dd'"
Resources:
  - https://attack.mitre.org/techniques/T1005/
  - https://man7.org/linux/man-pages/man1/dd.1.html
---
