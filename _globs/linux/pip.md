---
Name: pip
Description: "Python package installer. Installing packages with malicious setup.py executes arbitrary code. Can also download and run Python scripts directly."
Platform: linux
BinaryPath:
  - /usr/bin/pip
  - /usr/bin/pip3
  - /usr/local/bin/pip
  - /usr/local/bin/pip3
Category: execution
MitreID: T1059.006
Patterns:
  - Pattern: "pi?"
    Wildcards: ["?"]
    Notes: "Single wildcard replaces 'p' — matches pip and pip3 (with suffix)"
  - Pattern: "p?p"
    Wildcards: ["?"]
    Notes: "Wildcard replaces 'i' — note: also matches php; use full path or context to disambiguate"
  - Pattern: "pip[3]"
    Wildcards: ["[]"]
    Notes: "Character class on version suffix — matches pip3"
  - Pattern: "/usr/bin/pi?"
    Wildcards: ["?"]
    Notes: "Full path wildcard — resolves to /usr/bin/pip"
  - Pattern: "/???/bin/pip"
    Wildcards: ["?"]
    Notes: "Obfuscate /usr/ directory component"
  - Pattern: "$(ls /usr/bin/pi?)"
    Wildcards: ["?"]
    Notes: "ls resolves glob to /usr/bin/pip; command substitution executes it"
  - Pattern: "$'\\x70\\x69\\x70'"
    Wildcards: []
    Notes: "ANSI-C hex escapes expand to 'pip'"
PlatformNotes: |
  `pip install` with a local package runs `setup.py install`, executing arbitrary Python code as the installing user. `pip download` retrieves packages to disk without installing. The binary may be `pip3` on Python-3-only systems — use `pip*` or `pi?` globs to cover both.
Resources:
  - https://attack.mitre.org/techniques/T1059/006/
  - https://pip.pypa.io/en/stable/cli/pip_install/
---
