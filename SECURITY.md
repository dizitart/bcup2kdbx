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

### `@xmldom/xmldom`

`kdbxweb` declares `@xmldom/xmldom` `^0.7.4` and uses it to build and parse the inner KDBX
document. The 0.7.x line ended at 0.7.13 with no fixes, and every published advisory against
`<=0.8.14` is patched in **0.8.15**, so `@xmldom/xmldom` is **overridden to exactly `0.8.15`**.
`npm audit` reports no `@xmldom/xmldom` advisories with this override.

Earlier releases pinned 0.7.13 because 0.8.13+ normalises `\r\n` to `\n` when reading
values back. That turned out to affect only the read path. Both versions make `kdbxweb`
write tabs, CR and CRLF to the file byte for byte; the only difference on disk is that 0.8.x
also escapes `>`, which is equivalent XML. On load, 0.8.x applies XML 1.0 §2.11 end-of-line
handling (CR and CRLF become LF), which a conforming XML parser in any KeePass client is
required to do as well. In this tool the reader only runs in the post-write verification
pass, which already compares through that normalisation. `npm test` asserts both sides:
the raw decrypted XML keeps `\t` and `\r\n`, and the reloaded value is normalised.

The exact pin stays deliberate. **0.9.x** breaks `kdbxweb`'s XML builder (it throws on
save), so resolution must not drift there through a transitive bump. Do not run
`npm audit fix --force`: it downgrades `kdbxweb` and `buttercup`.

If you are auditing this project, the line to watch is `kdbxweb`'s
`dependencies["@xmldom/xmldom"]`, currently `^0.7.4`. A `kdbxweb` release that accepts and
works with a newer line makes the override unnecessary.

### `minimatch`

[GHSA-g3hv-75wg-m249](https://github.com/advisories/GHSA-g3hv-75wg-m249) (globparts DoS)
reaches the tree through `buttercup` → `webdav`. `webdav` is only instantiated for WebDAV
vault sources; this tool always opens the vault as a local `file` source, so the vulnerable
code is **not reachable**. npm's only offered fix is a `buttercup` downgrade, which is not
taken.

### `uuid`

`uuid` is overridden to `^11.1.1`, which clears its advisories with no behaviour change.

## What this tool does with your data

Everything runs locally. There is no telemetry and no network access at runtime.
Passwords are read from an interactive prompt with echo disabled, never from command-line
arguments or environment variables, so they do not land in shell history or `ps` output.
The only file written is the KDBX database you name.
