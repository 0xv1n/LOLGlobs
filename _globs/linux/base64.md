---
Name: base64
Description: "Encode or decode base64 data. Widely used to obfuscate payloads, bypass content filters, and encode exfiltrated data."
Platform: linux
BinaryPath:
  - /usr/bin/base64
  - /bin/base64
Category: encode-decode
MitreID: T1140
Patterns:
  - Pattern: "bas*4"
    Wildcards: ["*"]
    Notes: "Star matches 'e6' — short form that still requires 'bas' prefix and '4' suffix"
  - Pattern: "b??e64"
    Wildcards: ["?"]
    Notes: "Two wildcards replace 'as' in base"
  - Pattern: "b[a]se64"
    Wildcards: ["[]"]
    Notes: "Character class around 'a'"
  - Pattern: "base6[4]"
    Wildcards: ["[]"]
    Notes: "Character class on final digit"
  - Pattern: "/usr/bin/bas*4"
    Wildcards: ["*"]
    Notes: "Full path with star wildcard"
  - Pattern: "/???/bin/base64"
    Wildcards: ["?"]
    Notes: "Obfuscate /usr/ directory component"
  - Pattern: "$(ls /usr/bin/bas*4)"
    Wildcards: ["*"]
    Notes: "ls resolves glob to /usr/bin/base64; command substitution executes it"
  - Pattern: "$'\\x62\\x61\\x73\\x65\\x36\\x34'"
    Wildcards: []
    Notes: "ANSI-C hex escapes expand to 'base64'"
Resources:
  - https://attack.mitre.org/techniques/T1140/
  - https://man7.org/linux/man-pages/man1/base64.1.html
---
