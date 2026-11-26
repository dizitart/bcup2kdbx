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
// Self-check: build a Buttercup vault exercising every feature the converter
// claims to handle, run it through the real conversion, reload the KDBX bytes
// from disk and assert nothing was lost.
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
    AttachmentManager,
    Credentials,
    FileDatasource,
    Vault,
    VaultManager,
    VaultSource,
    init as buttercupInit
} from "buttercup";
import { vaultToKdbx, kdbxweb } from "./lib.js";

const VAULT_PASS = "source-master-pass";
const KDBX_PASS = "target-kdbx-pass";

function findGroup(group, name) {
    if (group.name === name) return group;
    for (const child of group.groups) {
        const hit = findGroup(child, name);
        if (hit) return hit;
    }
    return null;
}

function fieldText(entry, name) {
    const v = entry.fields.get(name);
    if (v === undefined) return undefined;
    return v instanceof kdbxweb.ProtectedValue ? v.getText() : String(v);
}

function isProtected(entry, name) {
    return entry.fields.get(name) instanceof kdbxweb.ProtectedValue;
}

async function buildVault(path) {
    const vault = Vault.createWithDefaults();

    const work = vault.createGroup("Work");
    const nested = work.createGroup("Servers").createGroup("Production");

    const login = work.createEntry("GitHub");
    login.setProperty("username", "octocat");
    login.setProperty("password", "hunter2");
    login.setProperty("url", "https://github.com");
    login.setProperty("Recovery Code", "abcd-efgh");
    login.setProperty("twofactor", "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub");
    login.setPropertyValueType("password", "password");
    login.setPropertyValueType("twofactor", "otp");
    login.addTags("dev", "critical");

    const card = vault.createGroup("Finance").createEntry("Visa");
    card.setProperty("username", "A Person");
    card.setProperty("password", "4111111111111111");
    card.setProperty("cvv", "123");
    card.setProperty("expiry", "01/2030");
    card.setAttribute("BC_ENTRY_FACADE_TYPE", "credit_card");
    card.setPropertyValueType("cvv", "password");

    const note = vault.createGroup("Notes").createEntry("Recipe");
    note.setProperty("note", "line one\nline two\nline three");
    note.setAttribute("BC_ENTRY_FACADE_TYPE", "note");
    note.setPropertyValueType("note", "note");

    const ssh = nested.createEntry("prod-box");
    ssh.setProperty("publicKey", "ssh-ed25519 AAAAC3Nz");
    ssh.setProperty("privateKey", "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END-----");
    ssh.setAttribute("BC_ENTRY_FACADE_TYPE", "ssh_key");
    ssh.setPropertyValueType("privateKey", "note");

    // XML-hostile values: these exercise the serialiser that kdbxweb uses to
    // build the inner KDBX document. Anything that mangles escaping shows up here.
    const nasty = vault.createGroup("Edge <&> Cases").createEntry("qu\"ote & <tag>");
    nasty.setProperty("username", "a<b>c&d\"e'f");
    nasty.setProperty("password", "]]>'\"&<>\\`$(){}[]");
    nasty.setProperty("note", "line1\nline2\ttab\r\ncrlf \u00e9\u4e2d\u6587 \ud83d\udd11");
    nasty.setProperty("cdata trap", "<![CDATA[oops]]>");
    nasty.setProperty("pi trap", "<?xml-stylesheet href=\"x\"?>");
    nasty.setProperty("comment trap", "<!-- not a comment -->");
    nasty.setPropertyValueType("password", "password");

    // Colliding custom field name: must not clobber the mapped Title.
    const collide = work.createEntry("Odd");
    collide.setProperty("Title", "shadow title");
    collide.setProperty("password", "p");

    // Deleted entry -> Trash.
    const doomed = work.createEntry("Deleted Thing");
    doomed.setProperty("password", "gone-but-kept");
    doomed.delete();

    const datasource = new FileDatasource(
        Credentials.fromDatasource({ type: "file", path }, VAULT_PASS)
    );
    await datasource.save(vault.format.history, Credentials.fromPassword(VAULT_PASS));
    return vault;
}

async function run() {
    buttercupInit();
    const dir = mkdtempSync(join(tmpdir(), "bcup2kdbx-test-"));
    const bcupPath = join(dir, "test.bcup");
    const kdbxPath = join(dir, "test.kdbx");

    try {
        await buildVault(bcupPath);

        const source = new VaultSource(
            "test",
            "file",
            await Credentials.fromDatasource({ type: "file", path: bcupPath }, VAULT_PASS).toSecureString()
        );
        const manager = new VaultManager({ autoUpdate: false });
        await manager.addSource(source);
        await source.unlock(Credentials.fromPassword(VAULT_PASS), { loadOfflineCopy: false });

        // Attachments: added through the real attachment manager so they are
        // encrypted in the vault exactly as Buttercup would store them.
        assert.ok(source.supportsAttachments(), "file source supports attachments");
        const attachTarget = source.vault
            .getAllEntries()
            .find((e) => e.getProperty("title") === "GitHub");
        const payload = Buffer.from("attachment-bytes\x00\x01\x02", "binary");
        await source.attachmentManager.setAttachment(
            attachTarget,
            AttachmentManager.newAttachmentID(),
            payload,
            "recovery-codes.txt",
            "text/plain"
        );

        const db = await vaultToKdbx(source, KDBX_PASS, { name: "Converted" });
        writeFileSync(kdbxPath, Buffer.from(await db.save()));

        // Reload from disk with a fresh credentials object - proves the bytes
        // on disk are a real, decryptable KDBX4 file. The decrypted inner XML is
        // captured on the way in so the written bytes can be checked directly,
        // independent of how the XML reader normalises them.
        const parseXml = kdbxweb.XmlUtils.parse;
        let innerXml = null;
        kdbxweb.XmlUtils.parse = (xml) => {
            innerXml = xml;
            return parseXml(xml);
        };
        let reloaded;
        try {
            reloaded = await kdbxweb.Kdbx.load(
                new Uint8Array(readFileSync(kdbxPath)).buffer,
                new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromString(KDBX_PASS))
            );
        } finally {
            kdbxweb.XmlUtils.parse = parseXml;
        }
        assert.ok(innerXml, "captured the decrypted inner XML");
        assert.ok(
            innerXml.includes("line1\nline2\ttab\r\ncrlf"),
            "tab and CRLF are written to the KDBX file byte for byte"
        );

        assert.equal(reloaded.versionMajor, 4, "must be KDBX 4");
        assert.equal(
            kdbxweb.ByteUtils.bytesToBase64(reloaded.header.kdfParameters.get("$UUID")),
            kdbxweb.Consts.KdfId.Argon2id,
            "must use Argon2id"
        );

        const root = reloaded.getDefaultGroup();

        // Nested structure survived.
        const prod = findGroup(root, "Production");
        assert.ok(prod, "nested group Work/Servers/Production exists");
        assert.equal(prod.parentGroup.name, "Servers");
        assert.equal(prod.parentGroup.parentGroup.name, "Work");

        // Login entry: standard field mapping + protection.
        const work = findGroup(root, "Work");
        const gh = work.entries.find((e) => fieldText(e, "Title") === "GitHub");
        assert.ok(gh, "GitHub entry exists");
        assert.equal(fieldText(gh, "UserName"), "octocat");
        assert.equal(fieldText(gh, "Password"), "hunter2");
        assert.equal(fieldText(gh, "URL"), "https://github.com");
        assert.ok(isProtected(gh, "Password"), "password field is protected");
        assert.equal(fieldText(gh, "Recovery Code"), "abcd-efgh", "custom field preserved under its own name");
        assert.equal(
            fieldText(gh, "otp"),
            "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
            "OTP lands in the KeePassXC `otp` field"
        );
        assert.ok(isProtected(gh, "otp"), "otp field is protected");
        assert.deepEqual([...gh.tags].sort(), ["critical", "dev", "login"], "tags + entry type");

        // Attachment survived as a KDBX binary with its original bytes.
        assert.equal(gh.binaries.size, 1, "one binary attached");
        const binary = gh.binaries.get("recovery-codes.txt");
        assert.ok(binary, "attachment kept its filename");
        const bytes = Buffer.from(binary.value ?? binary);
        assert.equal(bytes.toString("binary"), "attachment-bytes\x00\x01\x02", "attachment bytes intact");

        // Credit card: type is preserved as a tag and in custom data.
        const visa = findGroup(root, "Finance").entries[0];
        assert.equal(fieldText(visa, "Title"), "Visa");
        assert.equal(fieldText(visa, "UserName"), "A Person");
        assert.equal(fieldText(visa, "Password"), "4111111111111111");
        assert.equal(fieldText(visa, "cvv"), "123");
        assert.ok(isProtected(visa, "cvv"), "cvv is protected");
        assert.equal(fieldText(visa, "expiry"), "01/2030");
        assert.ok(visa.tags.includes("credit_card"));
        assert.equal(visa.customData.get("BC_ENTRY_FACADE_TYPE").value, "credit_card");

        // Multiline note -> Notes.
        const recipe = findGroup(root, "Notes").entries[0];
        assert.equal(fieldText(recipe, "Notes"), "line one\nline two\nline three");

        // SSH key: private key kept and protected.
        const box = prod.entries[0];
        assert.equal(fieldText(box, "publicKey"), "ssh-ed25519 AAAAC3Nz");
        assert.ok(fieldText(box, "privateKey").includes("BEGIN OPENSSH PRIVATE KEY"));
        assert.ok(isProtected(box, "privateKey"), "private key is protected");

        // Field-name collision did not overwrite the mapped Title.
        const odd = work.entries.find((e) => fieldText(e, "Title") === "Odd");
        assert.ok(odd, "colliding entry kept its real title");
        assert.equal(fieldText(odd, "Title (2)"), "shadow title", "colliding custom field renamed, not dropped");

        // XML-hostile values survived escaping byte for byte.
        const edge = findGroup(root, "Edge <&> Cases");
        assert.ok(edge, "group name with XML metacharacters preserved");
        const nastyEntry = edge.entries[0];
        assert.equal(fieldText(nastyEntry, "Title"), 'qu"ote & <tag>');
        assert.equal(fieldText(nastyEntry, "UserName"), 'a<b>c&d"e\'f');
        assert.equal(fieldText(nastyEntry, "Password"), ']]>\'"&<>\\`$(){}[]');
        // Tabs and CRs are written to the file intact (kdbxweb's serialiser emits
        // them verbatim; the raw-XML check below proves it) but kdbxweb's own
        // xmldom-based reader drops tabs and normalises CR/CRLF to LF on load, as
        // XML 1.0 section 2.11 requires of a conforming parser, so that is what we
        // observe here. Unicode, astral-plane characters and newlines must be exact.
        assert.equal(
            fieldText(nastyEntry, "Notes"),
            "line1\nline2tab\ncrlf \u00e9\u4e2d\u6587 \ud83d\udd11",
            "notes round-trip apart from the reader's known tab/CR handling"
        );
        assert.equal(fieldText(nastyEntry, "cdata trap"), "<![CDATA[oops]]>");
        assert.equal(fieldText(nastyEntry, "pi trap"), '<?xml-stylesheet href="x"?>');
        assert.equal(fieldText(nastyEntry, "comment trap"), "<!-- not a comment -->");

        // Trash -> recycle bin.
        assert.ok(reloaded.meta.recycleBinUuid, "recycle bin configured");
        const bin = reloaded.getGroup(reloaded.meta.recycleBinUuid);
        assert.ok(bin, "recycle bin group exists");
        const deleted = bin.entries.find((e) => fieldText(e, "Title") === "Deleted Thing");
        assert.ok(deleted, "deleted entry preserved in the recycle bin");
        assert.equal(fieldText(deleted, "Password"), "gone-but-kept");

        // Nothing from the source vault is missing.
        let total = 0;
        const walk = (g) => {
            total += g.entries.length;
            g.groups.forEach(walk);
        };
        walk(root);
        assert.equal(total, source.vault.getAllEntries().length, "entry count matches the source vault");

        console.log("All checks passed.");
    } finally {
        rmSync(dir, { recursive: true, force: true });
    }
}

run().catch((err) => {
    console.error(err);
    process.exit(1);
});
