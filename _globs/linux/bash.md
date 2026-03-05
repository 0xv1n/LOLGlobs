---
Name: bash
Description: "GNU Bourne Again Shell. Executing bash with -i or -c allows spawning interactive shells or running commands, commonly used in reverse shells."
Platform: linux
BinaryPath:
  - /bin/bash
  - /usr/bin/bash
Category: execution
MitreID: T1059.004
Patterns:
  - Pattern: "bas?"
    Wildcards: ["?"]
    Notes: "Wildcard replaces 'h'"
  - Pattern: "b*h"
    Wildcards: ["*"]
    Notes: "Star matches 'as'"
  - Pattern: "ba[s]h"
    Wildcards: ["[]"]
    Notes: "Character class around 's'"
  - Pattern: "b?sh"
    Wildcards: ["?"]
    Notes: "Wildcard replaces 'a'"
  - Pattern: "b?s?"
    Wildcards: ["?"]
    Notes: "Two wildcards"
  - Pattern: "/bin/bas?"
    Wildcards: ["?"]
    Notes: "Full path wildcard on last char"
  - Pattern: "/???/bash"
    Wildcards: ["?"]
    Notes: "Obfuscate /bin/ prefix"
  - Pattern: "/b?n/b*h"
    Wildcards: ["?", "*"]
    Notes: "Mixed wildcards across path and command"
  - Pattern: "b[a]sh"
    Wildcards: ["[]"]
    Notes: "Bracket class on second char"
  - Pattern: "/???/b*"
    Wildcards: ["?", "*"]
    Notes: "Highly obfuscated full path (may match other binaries)"
  - Pattern: "for p in /usr/{bin,local/bin}/bash; do \"$p\" && break; done"
    Wildcards: ["{}"]
    Notes: "Brace expansion in for loop — tries /usr/bin/bash then /usr/local/bin/bash"
  - Pattern: "$(ls /bin/bas?)"
    Wildcards: ["?"]
    Notes: "ls resolves glob to /bin/bash; command substitution executes it"
  - Pattern: "$'\\x62\\x61\\x73\\x68'"
    Wildcards: []
    Notes: "ANSI-C hex escapes expand to 'bash' before execution"
  - Pattern: "shopt -s extglob; /bin/+(ba)sh"
    Wildcards: ["+(...)"]
    Notes: "extglob +(ba) matches one or more occurrences of 'ba' — matches 'ba' in bash with full path"
Resources:
  - https://attack.mitre.org/techniques/T1059/004/
  - https://www.gnu.org/software/bash/manual/bash.html
---
