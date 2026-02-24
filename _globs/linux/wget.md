---
Name: wget
Description: "Non-interactive network downloader. Used to fetch files from HTTP/FTP servers, download payloads, or stage tools."
Platform: linux
BinaryPath:
  - /usr/bin/wget
  - /bin/wget
Category: download
MitreID: T1105
Patterns:
  - Pattern: "wge?"
    Wildcards: ["?"]
    Notes: "Wildcard replaces 't'"
  - Pattern: "w*t"
    Wildcards: ["*"]
    Notes: "Star matches 'ge'"
  - Pattern: "wg[e]t"
    Wildcards: ["[]"]
    Notes: "Character class around 'e'"
  - Pattern: "w?et"
    Wildcards: ["?"]
    Notes: "Wildcard replaces 'g'"
  - Pattern: "w?e?"
    Wildcards: ["?"]
    Notes: "Two wildcards replace 'g' and 't'"
  - Pattern: "/usr/bin/wge?"
    Wildcards: ["?"]
    Notes: "Full path wildcard on last char"
  - Pattern: "/???/bin/wget"
    Wildcards: ["?"]
    Notes: "Obfuscate /usr/ directory"
  - Pattern: "/???/???/w*"
    Wildcards: ["?", "*"]
    Notes: "Full path with mixed wildcards"
  - Pattern: "w[g]et"
    Wildcards: ["[]"]
    Notes: "Bracket class on second char"
  - Pattern: "wge[t]"
    Wildcards: ["[]"]
    Notes: "Bracket class matching last two chars (matches any single char in set)"
Resources:
  - https://attack.mitre.org/techniques/T1105/
  - https://www.gnu.org/software/wget/manual/wget.html
---
