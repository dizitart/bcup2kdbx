# Contributing to bcup2kdbx

Thanks for taking the time to help. This is a small, deliberately boring tool that moves
people's passwords between two formats, so the bar for changes is "provably does not lose
data" rather than "adds a feature".

## Getting set up

```bash
git clone https://github.com/dizitart/bcup2kdbx.git
cd bcup2kdbx
npm install
npm test
```

Node 20 or later. There is no build step, no transpiler and no linter config — the code is
plain ESM JavaScript that runs as-is.

## Ground rules for changes

- **Never hand-roll format handling.** Reading `.bcup` is `buttercup`'s job and writing
  KDBX is `kdbxweb`'s job. If something is missing, fix it upstream or work around it
  through their public APIs.
- **Every conversion change needs a test.** `test.js` builds a real Buttercup vault,
  converts it, reloads the KDBX bytes from disk and asserts on the result. Add your case
  there. A change to the mapping table with no assertion will not be merged.
- **Do not weaken protection.** Anything that could put a secret into an unprotected KDBX
  field, into argv, into the environment, or onto the terminal is a blocker.
- **Keep the diff small.** Match the surrounding style. Do not reformat untouched code.

## Testing

```bash
npm test
```

The self-check covers nested groups, all five Buttercup entry types, OTP fields,
attachments, field-name collisions and trashed entries. It creates its vault in a temp
directory and cleans up afterwards — it never touches a real vault.

To try the CLI end to end, export a throwaway vault from Buttercup and run:

```bash
node convert.js /path/to/throwaway.bcup /tmp/out.kdbx
```

Never attach a real `.bcup` file, a real `.kdbx` file, or a real password to an issue or
pull request. `.gitignore` excludes both extensions to make that harder to do by accident.

## Reporting bugs

Open an issue using the bug report template. A conversion bug is far easier to fix with a
*minimal synthetic vault* that reproduces it — a few entries you created solely for the
report — than with a description of your real vault.

## Security issues

Do not open a public issue. See [SECURITY.md](SECURITY.md).

## Releasing

Maintainers only.

1. Update `CHANGELOG.md`: move items out of `Unreleased` into a new version section, and
   update the link definitions at the bottom.
2. Bump `version` in `package.json` and commit both on `main`.
3. Publish a GitHub Release with the tag `vX.Y.Z`.

That triggers `.github/workflows/publish.yml`, which runs the tests, verifies the tag
matches `package.json`, and publishes to npm using **trusted publishing (OIDC)** — no npm
token exists anywhere in this repository. Provenance attestations are attached
automatically.

### One-time bootstrap

npm cannot configure a trusted publisher for a package that does not exist yet, and OIDC
cannot perform a package's very first publish (see
[npm/cli#8544](https://github.com/npm/cli/issues/8544)). So the first release is manual:

```bash
npm publish --access public
```

Then, on <https://www.npmjs.com/package/@dizitart/bcup2kdbx> → Settings → Trusted
publishers, add a GitHub Actions publisher with:

| Field | Value |
| --- | --- |
| Organization or user | `dizitart` |
| Repository | `bcup2kdbx` |
| Workflow filename | `publish.yml` |
| Environment name | `npm` |
| Allowed actions | `npm publish` |

Every release after that goes through the workflow with no token involved.

## Code of Conduct

By participating you agree to abide by the [Code of Conduct](CODE_OF_CONDUCT.md).

## Licence

Contributions are licensed under the [Apache License 2.0](LICENSE), the same terms as the
project.
