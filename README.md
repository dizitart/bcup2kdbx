# bcup2kdbx

[![CI](https://github.com/dizitart/bcup2kdbx/actions/workflows/ci.yml/badge.svg)](https://github.com/dizitart/bcup2kdbx/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@dizitart/bcup2kdbx.svg)](https://www.npmjs.com/package/@dizitart/bcup2kdbx)
[![node](https://img.shields.io/node/v/@dizitart/bcup2kdbx.svg)](https://nodejs.org)
[![licence](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](LICENSE)

Convert a [Buttercup](https://buttercup.pw) vault (`.bcup`) into a **KDBX 4** database you
can open in KeePassXC, KeePass 2, KeeWeb, Strongbox, or anything else that reads KeePass
files.

Groups, custom fields, attachments, tags, OTP secrets and the trash all come across. The
tool re-reads the file it just wrote and proves nothing was dropped before it exits.

```
$ bcup2kdbx ~/Buttercup.bcup ~/Buttercup.kdbx
Master password for /Users/you/Buttercup.bcup:
New password for /Users/you/Buttercup.kdbx:
Confirm password:
Unlocking vault...
Read 14 group(s), 231 entry/entries.
Converting...
Wrote /Users/you/Buttercup.kdbx (271104 bytes, KDBX 4, Argon2id).
Verifying...
Verified: every group, property value and attachment round-tripped.
```

## Install

```bash
npm install -g @dizitart/bcup2kdbx
```

Or run it once without installing:

```bash
npx @dizitart/bcup2kdbx vault.bcup vault.kdbx
```

Requires Node 20 or later.

## Use

```bash
bcup2kdbx <input.bcup> <output.kdbx> [options]
```

It prompts for the vault's master password, then twice for the password that will protect
the new KDBX file. **Passwords are never read from command-line arguments or environment
variables**, so they cannot leak into your shell history or into `ps` output.

| Option | Effect |
| --- | --- |
| `--name <text>` | Database name stored inside the KDBX file (default: the input filename) |
| `--out-keyfile <path>` | Additionally protect the KDBX file with a key file |
| `--no-verify` | Skip the post-write verification pass |

Exit codes: `0` success, `1` error, `2` verification found missing data.

### Getting a `.bcup` file

In the Buttercup desktop app the vault file on disk *is* the `.bcup` — for a local vault
it is the file you chose when you created it. For a cloud vault (Dropbox, Google Drive,
WebDAV), download the `.bcup` from that service first.

### After converting

Open the result in your KeePass client and spot-check a handful of entries before you
delete anything. The verification pass proves the data is in the file; it cannot prove
your particular client displays it the way you expect.

## What gets preserved

| Buttercup | KDBX 4 |
| --- | --- |
| Nested group tree | Nested group tree, same shape |
| `title` / `username` / `password` / `url` / `note` | `Title` / `UserName` / `Password` / `URL` / `Notes` |
| Any other property | Custom string field under its original name |
| Anything in the `Password` slot, anything typed `password` or `otp`, and `privateKey` | Stored as a **protected** value |
| A property typed `otp` (an `otpauth://` URI) | The `otp` field, which KeePassXC reads natively to generate TOTP codes |
| Entry attachments | KDBX binaries, original filename and bytes |
| Entry tags | Entry tags |
| Entry type (`login`, `website`, `credit_card`, `note`, `ssh_key`) | An extra tag, plus `BC_ENTRY_FACADE_TYPE` in entry CustomData |
| All Buttercup entry / group / vault attributes | CustomData on the entry / group / metadata |
| Trash | Recycle Bin |

Credit-card entries follow Buttercup's own layout: the card holder is `username` and the
card number is `password`, so they land in `UserName` and `Password`.

If a custom field collides with a slot already taken — an entry with both `title` and
`Title`, say — the canonical lower-case property wins the standard KDBX field and the other
is kept alongside it as `Title (2)`. Nothing is silently dropped.

### Two things that are not carried over verbatim

**Entry history.** Buttercup stores a field-level changelog, not entry snapshots.
Reconstructing KDBX history entries from it would fabricate "previous versions" that never
existed, so only current values are written.

**Entry timestamps.** Buttercup stores none of its own. Creation and modification times are
derived from the earliest and latest entry in that changelog — the best answer available,
but derived rather than recorded.

### Tabs and carriage returns

If a field value contains a tab or a `\r\n` line ending, the converter prints a note during
verification. The characters **are written to the KDBX file intact** — kdbxweb's serialiser
emits them verbatim — but kdbxweb's own XML reader drops tabs when it loads the file back,
so the verification pass can only match those values after normalising. Whether a tab
survives into your KeePass client depends on that client's XML parser; a spec-compliant
parser keeps tabs in element content and collapses `\r\n` to `\n`.

This affects display only. Nothing is dropped from the file that is written.

## How it works

Reading is done by [`buttercup`](https://www.npmjs.com/package/buttercup) — Buttercup's own
vault stack, so decryption, format handling and attachment decryption are exactly what the
Buttercup app does. Writing is [`kdbxweb`](https://www.npmjs.com/package/kdbxweb). Neither
format is parsed or serialised by hand anywhere in this repository.

`kdbxweb` ships no Argon2 implementation, so [`hash-wasm`](https://www.npmjs.com/package/hash-wasm)
supplies one. Output is KDBX 4 with **Argon2id** key derivation.

Everything runs locally. There is no network access at runtime and no telemetry.

### Use as a library

```js
import { openVault, vaultToKdbx } from "@dizitart/bcup2kdbx";
import { writeFileSync } from "node:fs";

const source = await openVault("vault.bcup", vaultPassword);
const db = await vaultToKdbx(source, newPassword, { name: "My Vault" });
writeFileSync("vault.kdbx", Buffer.from(await db.save()));
await source.lock();
```

`vaultToKdbx` returns a `kdbxweb` `Kdbx` instance, so you can modify it further before
saving.

## Verification

After writing, the converter reloads the file from disk and checks that every group, every
property value and every attachment from the source vault is present in the output. If
anything is missing it lists what and exits `2`.

`npm test` runs an end-to-end self-check against a synthetic vault covering nested groups,
all five entry types, OTP fields, attachments, field-name collisions and trashed entries.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Bug reports are welcome — please build a synthetic
vault to demonstrate the problem rather than sending anything real.

Security problems go through [private reporting](SECURITY.md), never a public issue.

## Licence

[Apache License 2.0](LICENSE). Copyright 2026 Dizitart.
