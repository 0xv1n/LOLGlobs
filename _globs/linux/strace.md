---
Name: strace
Description: "System call tracer. Can monitor running processes, extract secrets from memory, and trace file/network operations for reconnaissance."
Platform: linux
BinaryPath:
  - /usr/bin/strace
  - /bin/strace
Category: discovery
MitreID: T1057
Patterns:
  - Pattern: "st*e"
    Wildcards: ["*"]
    Notes: "Star matches 'rac' — may match other st*e binaries"
  - Pattern: "str?ce"
    Wildcards: ["?"]
    Notes: "Single wildcard replaces 'a'"
  - Pattern: "s*ce"
    Wildcards: ["*"]
    Notes: "Star matches 'tra' — broader pattern"
  - Pattern: "strac[e]"
    Wildcards: ["[]"]
    Notes: "Character class on final char"
  - Pattern: "/usr/bin/str?ce"
    Wildcards: ["?"]
    Notes: "Full path with single wildcard"
  - Pattern: "/???/bin/str?ce"
    Wildcards: ["?"]
    Notes: "Obfuscate /usr/ and 'a' in strace"
  - Pattern: "$(ls /usr/bin/str?ce)"
    Wildcards: ["?"]
    Notes: "ls resolves glob to /usr/bin/strace; command substitution executes it"
  - Pattern: "$'\\x73\\x74\\x72\\x61\\x63\\x65'"
    Wildcards: []
    Notes: "ANSI-C hex escapes expand to 'strace'"
PlatformNotes: |
  strace can extract credentials by tracing process syscalls: `strace -p <pid> -e read 2>&1 | grep -i pass`. If strace has sudo permissions, it enables shell escapes: `sudo strace -o /dev/null /bin/bash`. GTFOBins documents strace as a sudo escape vector.
Resources:
  - https://attack.mitre.org/techniques/T1057/
  - https://gtfobins.github.io/gtfobins/strace/
  - https://man7.org/linux/man-pages/man1/strace.1.html
---
