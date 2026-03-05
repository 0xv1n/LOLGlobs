---
Name: gdb
Description: "GNU debugger. Can execute arbitrary shell commands via the 'shell' command, call library functions directly, and load shared libraries — making it a code execution primitive."
Platform: linux
BinaryPath:
  - /usr/bin/gdb
  - /bin/gdb
Category: execution
MitreID: T1059
Patterns:
  - Pattern: "g?b"
    Wildcards: ["?"]
    Notes: "Single wildcard replaces 'd'"
  - Pattern: "gd[b]"
    Wildcards: ["[]"]
    Notes: "Character class on last char"
  - Pattern: "/usr/bin/g?b"
    Wildcards: ["?"]
    Notes: "Full path with wildcard"
  - Pattern: "/???/bin/g?b"
    Wildcards: ["?"]
    Notes: "Obfuscate /usr/ and 'd' in gdb"
  - Pattern: "$(ls /usr/bin/g?b)"
    Wildcards: ["?"]
    Notes: "ls resolves glob to /usr/bin/gdb; command substitution executes it"
  - Pattern: "$'\\x67\\x64\\x62'"
    Wildcards: []
    Notes: "ANSI-C hex escapes expand to 'gdb'"
PlatformNotes: |
  gdb can run shell commands with `gdb -batch -ex 'shell whoami'`. It can also call C functions directly: `gdb -batch -ex 'call system("id")'`. If gdb has SUID or sudo permissions, it becomes a privilege escalation path. GTFOBins documents gdb as a file read/write and shell escape vector.
Resources:
  - https://attack.mitre.org/techniques/T1059/
  - https://gtfobins.github.io/gtfobins/gdb/
---
