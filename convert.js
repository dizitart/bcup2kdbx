#!/usr/bin/env node
/*
 * Copyright 2026 Dizitart
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { createInterface } from "node:readline";
import { openVault, vaultToKdbx, kdbxweb } from "./lib.js";

function usage() {
    console.error(`Usage: bcup2kdbx <input.bcup> <output.kdbx> [options]

Options:
  --name <text>        Database name stored in the KDBX file (default: input filename)
  --out-keyfile <path> Additionally protect the KDBX file with this key file
  --no-verify          Skip the post-write verification pass
`);
    process.exit(1);
}

function parseArgs(argv) {
    const opts = { positional: [], name: null, outKeyfile: null, verify: true };
    for (let i = 0; i < argv.length; i++) {
        const a = argv[i];
        if (a === "--name") opts.name = argv[++i];
        else if (a === "--out-keyfile") opts.outKeyfile = argv[++i];
        else if (a === "--no-verify") opts.verify = false;
        else if (a.startsWith("-")) usage();
        else opts.positional.push(a);
    }
    if (opts.positional.length !== 2) usage();
    if (opts.name === undefined || opts.outKeyfile === undefined) usage();
    return opts;
}

// One readline interface for the whole run, and all prompts are collected up
// front: closing it between questions tears down stdin, and a piped (non-TTY)
// stdin ends as soon as it is drained.
let rl = null;
let lines = null;
async function promptHidden(question) {
    const tty = Boolean(process.stdin.isTTY);
    if (!rl) {
        rl = createInterface({ input: process.stdin, output: process.stderr, terminal: tty });
        if (tty) rl._writeToOutput = () => {}; // sudo-style: echo nothing while typing
        lines = rl[Symbol.asyncIterator]();
    }
    process.stderr.write(question);
    const { value, done } = await lines.next();
    process.stderr.write("\n");
    if (done) throw new Error("input ended before all passwords were given");
    return value;
}

function closePrompt() {
    if (rl) {
        rl.close();
        rl = null;
    }
}

// kdbxweb reads the inner KDBX document through xmldom, which drops tab
// characters from text nodes on load. The bytes written to disk keep them -
// kdbxweb's serialiser emits `<Value>a\tb</Value>` verbatim - so a value that
// matches only after this normalisation was written correctly and read back
// lossily, not lost. Compare through it rather than reporting a false failure.
function normaliseXmlText(value) {
    return value.replace(/\r\n?/g, "\n").replace(/\t/g, "");
}

function walkGroups(group, fn) {
    fn(group);
    for (const child of group.groups) walkGroups(child, fn);
}

// Prove nothing was dropped: every source property value must be present in the
// reloaded KDBX entry that carries the same Buttercup entry ID.
function verify(vault, db) {
    const entriesById = new Map();
    const groupIds = new Set();
    walkGroups(db.getDefaultGroup(), (g) => {
        const gid = g.customData?.get("bc_group_id")?.value;
        if (gid) groupIds.add(gid);
        for (const e of g.entries) {
            const id = e.customData?.get("bc_entry_id")?.value;
            if (id) entriesById.set(id, e);
        }
    });

    const problems = [];
    const normalised = [];
    for (const group of vault.getAllGroups()) {
        if (!groupIds.has(group.id) && !group.isTrash()) {
            problems.push(`group missing from KDBX: "${group.getTitle()}" (${group.id})`);
        }
    }
    for (const entry of vault.getAllEntries()) {
        const kentry = entriesById.get(entry.id);
        if (!kentry) {
            problems.push(`entry missing from KDBX: ${entry.id}`);
            continue;
        }
        const values = new Set(
            [...kentry.fields.values()].map((v) =>
                v instanceof kdbxweb.ProtectedValue ? v.getText() : String(v ?? "")
            )
        );
        for (const [property, value] of Object.entries(entry.getProperty())) {
            if (values.has(value)) continue;
            const relaxed = new Set([...values].map(normaliseXmlText));
            if (relaxed.has(normaliseXmlText(value))) {
                normalised.push(`entry ${entry.id}: property "${property}"`);
                continue;
            }
            problems.push(`entry ${entry.id}: value of property "${property}" not found in KDBX`);
        }
        const attachmentCount = Object.keys(entry.getAttribute() || {}).filter((k) =>
            k.startsWith("BC_ENTRY_ATTACHMENT:")
        ).length;
        if (kentry.binaries.size !== attachmentCount) {
            problems.push(
                `entry ${entry.id}: ${attachmentCount} attachment(s) in vault, ${kentry.binaries.size} binary/binaries in KDBX`
            );
        }
    }
    return { problems, normalised };
}

async function main() {
    const opts = parseArgs(process.argv.slice(2));
    const [input, output] = opts.positional;

    const vaultPassword = await promptHidden(`Master password for ${input}: `);
    if (!vaultPassword) throw new Error("no vault password given");
    const outPassword = await promptHidden(`New password for ${output}: `);
    if (!outPassword) throw new Error("no output password given");
    const confirm = await promptHidden("Confirm password: ");
    if (outPassword !== confirm) throw new Error("passwords do not match");

    closePrompt();

    const keyfile = opts.outKeyfile
        ? new Uint8Array(readFileSync(opts.outKeyfile)).buffer
        : null;

    process.stderr.write("Unlocking vault...\n");
    const source = await openVault(input, vaultPassword);
    const vault = source.vault;
    process.stderr.write(
        `Read ${vault.getAllGroups().length} group(s), ${vault.getAllEntries().length} entry/entries.\n`
    );

    process.stderr.write("Converting...\n");
    const db = await vaultToKdbx(source, outPassword, { name: opts.name, keyfile });
    const bytes = await db.save();
    writeFileSync(output, Buffer.from(bytes));
    process.stderr.write(`Wrote ${output} (${bytes.byteLength} bytes, KDBX 4, Argon2id).\n`);

    if (opts.verify) {
        process.stderr.write("Verifying...\n");
        const credentials = new kdbxweb.Credentials(
            kdbxweb.ProtectedValue.fromString(outPassword),
            keyfile
        );
        const reloaded = await kdbxweb.Kdbx.load(
            new Uint8Array(readFileSync(output)).buffer,
            credentials
        );
        const { problems, normalised } = verify(vault, reloaded);
        if (normalised.length) {
            process.stderr.write(
                `Note: ${normalised.length} value(s) contain tab or CR characters. They are written to the\n` +
                    `      KDBX file intact, but kdbxweb's XML reader normalises them on load, so they could\n` +
                    `      only be matched after normalisation. How they display depends on your client:\n`
            );
            for (const n of normalised.slice(0, 10)) process.stderr.write(`      - ${n}\n`);
            if (normalised.length > 10) {
                process.stderr.write(`      ... and ${normalised.length - 10} more\n`);
            }
        }
        if (problems.length) {
            console.error(`\nVERIFICATION FAILED (${problems.length} problem(s)):`);
            for (const p of problems.slice(0, 50)) console.error(`  - ${p}`);
            if (problems.length > 50) console.error(`  ... and ${problems.length - 50} more`);
            process.exitCode = 2;
            return;
        }
        process.stderr.write("Verified: every group, property value and attachment round-tripped.\n");
    }

    await source.lock();
}

main()
    .catch((err) => {
        console.error(`Error: ${err.message}`);
        process.exitCode = 1;
    })
    .finally(closePrompt);
