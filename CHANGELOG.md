# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
- `@xmldom/xmldom` pinned to exactly `0.7.13`. Both advisories against it are first patched
  in 0.8.13, but 0.9.x breaks `kdbxweb`'s XML builder and 0.8.x silently normalises `\r\n`
  to `\n` when reading values back. Neither advisory is reachable through this tool —
  `kdbxweb` never serialises comment or processing-instruction nodes. See
  [SECURITY.md](SECURITY.md) for the full analysis.

[Unreleased]: https://github.com/dizitart/bcup2kdbx/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/dizitart/bcup2kdbx/releases/tag/v1.0.0
