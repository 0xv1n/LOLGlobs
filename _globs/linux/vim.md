---
Name: vim
Description: "Vi Improved text editor. Can execute shell commands via :!cmd, spawn interactive shells, read and write arbitrary files, and is a common sudo escape vector."
Platform: linux
BinaryPath:
  - /usr/bin/vim
  - /bin/vim
  - /usr/bin/vi
Category: execution
MitreID: T1059
Patterns:
  - Pattern: "vi?"
    Wildcards: ["?"]
    Notes: "Single wildcard replaces 'm' — also matches 'vi' binary if present"
  - Pattern: "v?m"
    Wildcards: ["?"]
    Notes: "Wildcard replaces 'i'"
  - Pattern: "v[i]m"
    Wildcards: ["[]"]
    Notes: "Character class around 'i'"
  - Pattern: "/usr/bin/vi?"
    Wildcards: ["?"]
    Notes: "Full path wildcard on last char"
  - Pattern: "/???/bin/vi?"
    Wildcards: ["?"]
    Notes: "Obfuscate /usr/ and last char of vim"
  - Pattern: "$(ls /usr/bin/vi?)"
    Wildcards: ["?"]
    Notes: "ls resolves glob to /usr/bin/vim; command substitution executes it"
  - Pattern: "$'\\x76\\x69\\x6d'"
    Wildcards: []
    Notes: "ANSI-C hex escapes expand to 'vim'"
PlatformNotes: |
  vim can execute shell commands: `vim -c ':!whoami' -c ':q'`. For a persistent shell: `vim -c ':set shell=/bin/bash' -c ':shell'`. If vim runs with sudo: `sudo vim -c ':!bash'` drops to a root shell. GTFOBins documents vim as a file read/write, SUID, and sudo escape vector.
Resources:
  - https://attack.mitre.org/techniques/T1059/
  - https://gtfobins.github.io/gtfobins/vim/
---
