---
Name: xxd
Description: "Hex dump and reverse hex dump utility. Can convert binaries to hex and reconstruct binaries from hex — useful for payload staging and encoding."
Platform: linux
BinaryPath:
  - /usr/bin/xxd
  - /bin/xxd
Category: encode-decode
MitreID: T1140
Patterns:
  - Pattern: "x?d"
    Wildcards: ["?"]
    Notes: "Single wildcard replaces 'x'"
  - Pattern: "xx[d]"
    Wildcards: ["[]"]
    Notes: "Character class on last char"
  - Pattern: "x*d"
    Wildcards: ["*"]
    Notes: "Star matches 'x'"
  - Pattern: "/usr/bin/x?d"
    Wildcards: ["?"]
    Notes: "Full path, wildcard on middle char"
  - Pattern: "/???/bin/x?d"
    Wildcards: ["?"]
    Notes: "Obfuscate /usr/ and the middle 'x'"
  - Pattern: "$(ls /usr/bin/x?d)"
    Wildcards: ["?"]
    Notes: "ls resolves glob to /usr/bin/xxd; command substitution executes it"
  - Pattern: "$'\\x78\\x78\\x64'"
    Wildcards: []
    Notes: "ANSI-C hex escapes expand to 'xxd'"
PlatformNotes: |
  xxd can encode a binary to hex (`xxd -p file`) and reconstruct it (`xxd -r -p hexstring > file`). Useful for transferring binaries as hex strings over text channels. Combined with echo: `echo '7f454c46...' | xxd -r -p > /tmp/elf && chmod +x /tmp/elf`.
Resources:
  - https://attack.mitre.org/techniques/T1140/
  - https://linux.die.net/man/1/xxd
---
