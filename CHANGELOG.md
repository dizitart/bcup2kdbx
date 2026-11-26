# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- `@xmldom/xmldom` override moved from `0.7.13` to exactly `0.8.15`, clearing all fifteen
  advisories `npm audit` reports against `<=0.8.14`. The `\r\n` normalisation that kept the
  previous pin affects only how values are read back, not what is written: tabs, CR and
  CRLF reach the KDBX file byte for byte under both versions. `npm test` now checks the raw
  decrypted XML for this directly. See [SECURITY.md](SECURITY.md).
- Documented the `minimatch` advisory (GHSA-g3hv-75wg-m249) reached via `buttercup` →
  `webdav`; it is not reachable because only the local file vault source is used.

## [1.0.0] - 2026-08-30

### Added

- `bcup2kdbx <input.bcup> <output.kdbx>` CLI that converts a Buttercup vault into a
  KDBX 4 database. Reading uses Buttercup's own vault stack (`buttercup`), writing uses
  `kdbxweb`; no vault or database format handling is implemented by hand.
- Interactive, no-echo password prompts for the source vault and the target database.
  Passwords are never read from argv or the environment.
- KDBX 4 output with Argon2id key derivation, backed by `hash-wasm` (`kdbxweb` ships no
  Argon2 implementation of its own).
- Full structural conversion: nested groups, standard fields (`Title`, `UserName`,
  `Password`, `URL`, `Notes`), arbitrary custom fields, entry tags, entry types,
  attachments as KDBX binaries, and Buttercup's Trash as the KDBX Recycle Bin.
- OTP fields written to the `otp` field that KeePassXC reads natively.
- All Buttercup entry, group and vault attributes preserved in KDBX CustomData.
- Entry timestamps derived from Buttercup's per-field change log.
- Post-write verification pass: the file is reloaded from disk and every group, property
  value and attachment from the source vault is confirmed present. Exits `2` on failure.
- `--name`, `--out-keyfile` and `--no-verify` options.
- End-to-end self-check (`npm test`) covering nested groups, all five Buttercup entry
  types, OTP fields, attachments, field-name collisions, XML-hostile field values and
  trashed entries.

### Security

- `uuid` overridden to `^11.1.1` to clear
  [GHSA-w5hq-g745-h8pq](https://github.com/advisories/GHSA-w5hq-g745-h8pq) in the
  transitive dependency tree.
- `@xmldom/xmldom` pinned to exactly `0.7.13`. Five advisories affect it, all first patched
  in 0.8.12/0.8.13, but the 0.7.x line `kdbxweb` accepts ended at 0.7.13 with no fix: 0.9.x
  breaks `kdbxweb`'s XML builder and 0.8.13+ silently normalises `\r\n` to `\n` when reading
  values back. Four of the five are structurally unreachable here — `kdbxweb` never creates
  comment, processing-instruction, CDATA or DocumentType nodes. The fifth is a recursion
  DoS needing ~8000 levels of group nesting to crash a local CLI before it writes anything.
  See [SECURITY.md](SECURITY.md) for the per-advisory assessment.

[Unreleased]: https://github.com/dizitart/bcup2kdbx/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/dizitart/bcup2kdbx/releases/tag/v1.0.0
