---
Name: curl
Description: "Transfer data to or from a server. Commonly used for downloading payloads, exfiltration, and C2 communication."
Platform: linux
BinaryPath:
  - /usr/bin/curl
  - /bin/curl
Category: download
MitreID: T1105
Patterns:
  - Pattern: "cur?"
    Wildcards: ["?"]
    Notes: "Single wildcard replaces 'l'"
  - Pattern: "c*l"
    Wildcards: ["*"]
    Notes: "Star matches 'ur'"
  - Pattern: "cu[r]l"
    Wildcards: ["[]"]
    Notes: "Character class around 'r'"
  - Pattern: "c?r?"
    Wildcards: ["?"]
    Notes: "Two wildcards replace 'u' and 'l'"
  - Pattern: "/usr/bin/cur?"
    Wildcards: ["?"]
    Notes: "Full path, wildcard on last char"
  - Pattern: "/???/bin/curl"
    Wildcards: ["?"]
    Notes: "Obfuscate /usr/ prefix"
  - Pattern: "/usr/*/cur?"
    Wildcards: ["*", "?"]
    Notes: "Combined wildcards on directory and command"
  - Pattern: "cur[l]"
    Wildcards: ["[]"]
    Notes: "Bracket class on final char"
  - Pattern: "c[u]rl"
    Wildcards: ["[]"]
    Notes: "Bracket class on second char"
  - Pattern: "/???/???/c*"
    Wildcards: ["?", "*"]
    Notes: "Full path obfuscation with mixed wildcards"
  - Pattern: "for p in /usr/{bin,sbin}/curl; do \"$p\" && break; done"
    Wildcards: ["{}"]
    Notes: "Brace expansion in for loop — tries both path alternatives"
  - Pattern: "$(ls /usr/bin/cur?)"
    Wildcards: ["?"]
    Notes: "ls resolves the glob to full path; command substitution executes the result"
  - Pattern: "$'\\x63\\x75\\x72\\x6c'"
    Wildcards: []
    Notes: "ANSI-C hex escapes expand to the string 'curl' before execution"
Resources:
  - https://attack.mitre.org/techniques/T1105/
  - https://curl.se/docs/manpage.html
---
