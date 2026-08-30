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

`npm audit` reports five advisories against `@xmldom/xmldom` 0.7.x, which `kdbxweb` pins
(`^0.7.4`) and uses to build the inner KDBX document. Each was assessed against how
`kdbxweb` actually uses the library, and the corresponding Dependabot alerts are dismissed
with these reasons.

Four require serialising a node type that `kdbxweb` never creates. Its source contains zero
references to `createComment`, `createProcessingInstruction`, `createCDATASection` or
`createDocumentType`; the KDBX document is built exclusively from element and text nodes,
and field values are escaped as text. They are **not reachable** through this tool:

| Advisory | Requires | Why it cannot happen here |
| --- | --- | --- |
| [GHSA-j759-j44w-7fr8](https://github.com/advisories/GHSA-j759-j44w-7fr8) | Serialising a **comment** node | `kdbxweb` never creates one |
| [GHSA-x6wf-f3px-wcqx](https://github.com/advisories/GHSA-x6wf-f3px-wcqx) | Serialising a **processing instruction** | `kdbxweb` never creates one |
| [GHSA-wh4c-j3r5-mjhp](https://github.com/advisories/GHSA-wh4c-j3r5-mjhp) | `]]>` inside a **CDATA section** | `kdbxweb` never creates one |
| [GHSA-f6ww-3ggp-fr8h](https://github.com/advisories/GHSA-f6ww-3ggp-fr8h) | A **DocumentType** with controlled `internalSubset` / `publicId` / `systemId` | No DOCTYPE is emitted at all |

The test suite corroborates this: field values of `<!-- not a comment -->`,
`<?xml-stylesheet href="x"?>` and `<![CDATA[oops]]>` all round-trip escaped as text.

The fifth is different and is **reachable**, so it is recorded as tolerable risk rather
than dismissed as unused:

- [GHSA-2v35-w6hq-6mfw](https://github.com/advisories/GHSA-2v35-w6hq-6mfw) — uncontrolled
  recursion in DOM traversal. `kdbxweb` does use `serializeToString`, `getElementsByTagName`
  and `textContent`, so a `.bcup` with pathologically deep group nesting can exhaust the
  call stack. Measured on this codebase: fine at 4000 levels of nesting, `RangeError` at
  8000. The impact is a crash of a local, one-shot CLI acting on a file the user chose to
  convert, and it fails before anything is written — no data loss, no code execution, no
  privilege boundary crossed.

### Why not just upgrade

All five are first patched in 0.8.12/0.8.13. The 0.7.x line that `kdbxweb` accepts ended at
0.7.13 with no fix, so there is no patched version inside its range. Both ways out are worse
than the exposure above:

- **0.9.x** breaks `kdbxweb`'s XML builder outright — it throws on save.
- **0.8.13+** works, but introduces a **data-fidelity regression**: it normalises `\r\n` to
  `\n` when reading values back, which 0.7.13 does not. Silently altering the contents of a
  password database is a worse outcome than the residual risk above.

`@xmldom/xmldom` is therefore **pinned to exactly `0.7.13`** in `overrides`, so resolution
is deterministic and cannot drift into either broken state through a transitive bump.

`uuid` is overridden to `^11.1.1`, which clears its advisories with no behaviour change.

This will be revisited whenever `kdbxweb` widens its range. If you are auditing this
project, that is the single line to watch: `kdbxweb`'s `dependencies["@xmldom/xmldom"]`,
currently `^0.7.4`. A `kdbxweb` release that accepts 0.9.x and works with it clears all five
at once.

## What this tool does with your data

Everything runs locally. There is no telemetry and no network access at runtime.
Passwords are read from an interactive prompt with echo disabled, never from command-line
arguments or environment variables, so they do not land in shell history or `ps` output.
The only file written is the KDBX database you name.
