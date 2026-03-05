---
Name: screen
Description: "Terminal multiplexer. Can create persistent sessions that survive logout, run background processes, and escape restricted shells."
Platform: linux
BinaryPath:
  - /usr/bin/screen
  - /bin/screen
Category: execution
MitreID: T1059.004
Patterns:
  - Pattern: "scree?"
    Wildcards: ["?"]
    Notes: "Single wildcard replaces 'n'"
  - Pattern: "s*n"
    Wildcards: ["*"]
    Notes: "Star matches 'cree' — broad pattern, may match other s*n binaries"
  - Pattern: "scr*n"
    Wildcards: ["*"]
    Notes: "Star matches 'ee' — more specific"
  - Pattern: "scree[n]"
    Wildcards: ["[]"]
    Notes: "Character class on final char"
  - Pattern: "/usr/bin/scree?"
    Wildcards: ["?"]
    Notes: "Full path with wildcard on last char"
  - Pattern: "/???/bin/screen"
    Wildcards: ["?"]
    Notes: "Obfuscate /usr/ directory"
  - Pattern: "$(ls /usr/bin/scree?)"
    Wildcards: ["?"]
    Notes: "ls resolves glob to /usr/bin/screen; command substitution executes it"
  - Pattern: "$'\\x73\\x63\\x72\\x65\\x65\\x6e'"
    Wildcards: []
    Notes: "ANSI-C hex escapes expand to 'screen'"
PlatformNotes: |
  screen -dmS name cmd runs a detached named session. Sessions survive SSH disconnects. If screen has SUID permissions: `screen -x 'attacker/cmd'` can escape to a shell. GTFOBins documents screen as a SUID privilege escalation vector.
Resources:
  - https://attack.mitre.org/techniques/T1059/004/
  - https://gtfobins.github.io/gtfobins/screen/
  - https://man7.org/linux/man-pages/man1/screen.1.html
---
