# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.x | Yes |

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report privately through GitHub's
[private vulnerability reporting](https://github.com/dizitart/bcup2kdbx/security/advisories/new)
on this repository. You should get an acknowledgement within 7 days and a fix or a plan
within 30 days.

## Scope

This tool decrypts a password vault and writes another one, so the interesting reports are:

- Secrets leaking outside the process — to disk, logs, argv, environment, or the terminal.
- A converted field losing its protected status in the KDBX output.
- Data loss or silent truncation during conversion.
- Weakened key derivation or cipher parameters in the written database.

Vulnerabilities in `buttercup`, `kdbxweb` or `hash-wasm` themselves belong upstream, though
we appreciate a heads-up so we can pin or patch.

## Known advisories in the dependency tree

`npm audit` reports two advisories against `@xmldom/xmldom` 0.7.x, which `kdbxweb` pins
(`^0.7.4`) and uses to build the inner KDBX document:

- [GHSA-x6wf-f3px-wcqx](https://github.com/advisories/GHSA-x6wf-f3px-wcqx) — node injection
  through unvalidated **processing instruction** serialization
- [GHSA-j759-j44w-7fr8](https://github.com/advisories/GHSA-j759-j44w-7fr8) — node injection
  through unvalidated **comment** serialization

Both require the application to serialize a processing instruction or a comment node built
from attacker-controlled input. `kdbxweb` builds the KDBX document exclusively from element
and text nodes; it never creates comment or processing-instruction nodes, and vault field
values reach the document as text nodes, which are escaped. Neither vector is reachable
through this tool.

Overriding to `@xmldom/xmldom` 0.9.x breaks `kdbxweb`'s XML builder outright, and 0.8.x
introduces a **data-fidelity regression**: it normalises `\r\n` to `\n` when reading values
back, which 0.7.13 does not. Silently altering the contents of a password database is a
worse outcome than carrying two unreachable advisories, so the override is deliberately not
applied. `uuid` is overridden to `^11.1.1`, which clears its advisories with no behaviour
change.

This decision will be revisited whenever `kdbxweb` widens its `@xmldom/xmldom` range.

## What this tool does with your data

Everything runs locally. There is no telemetry and no network access at runtime.
Passwords are read from an interactive prompt with echo disabled, never from command-line
arguments or environment variables, so they do not land in shell history or `ps` output.
The only file written is the KDBX database you name.
