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
// Buttercup vault -> KDBX4 conversion. No hand-rolled format code: reading is
// buttercup's own vault stack, writing is kdbxweb.
import { basename } from "node:path";
import { argon2d, argon2id } from "hash-wasm";
import { Credentials, VaultManager, VaultSource, createEntryFacade, init as buttercupInit } from "buttercup";
import kdbxweb from "kdbxweb";

// kdbxweb ships no argon2; wire hash-wasm in once per process.
let argon2Ready = false;
export function installArgon2() {
    if (argon2Ready) return;
    kdbxweb.CryptoEngine.setArgon2Impl(
        async (password, salt, memory, iterations, length, parallelism, type, version) => {
            if (version !== 0x13) throw new Error(`unsupported argon2 version 0x${version.toString(16)}`);
            const fn = type === kdbxweb.CryptoEngine.Argon2TypeArgon2id ? argon2id : argon2d;
            const hash = await fn({
                password: new Uint8Array(password),
                salt: new Uint8Array(salt),
                parallelism,
                iterations,
                memorySize: memory, // kdbxweb already divides by 1024, so this is KiB
                hashLength: length,
                outputType: "binary"
            });
            return hash.buffer;
        }
    );
    argon2Ready = true;
}

// --- Buttercup side ------------------------------------------------------

const ATTR = {
    attachmentPrefix: "BC_ENTRY_ATTACHMENT:",
    facadeType: "BC_ENTRY_FACADE_TYPE",
    fieldTypePrefix: "BC_ENTRY_FIELD_TYPE:",
    tags: "BC_ENTRY_TAGS"
};

export async function openVault(path, password) {
    buttercupInit();
    const credentials = Credentials.fromDatasource({ type: "file", path }, password);
    const source = new VaultSource(basename(path), "file", await credentials.toSecureString());
    const manager = new VaultManager({ autoUpdate: false });
    await manager.addSource(source);
    await source.unlock(Credentials.fromPassword(password), { loadOfflineCopy: false });
    return source;
}

// --- Field mapping -------------------------------------------------------

// The five Buttercup properties with a native KDBX home. Everything else
// becomes a custom string field under its original name.
const STANDARD = new Map([
    ["title", "Title"],
    ["username", "UserName"],
    ["password", "Password"],
    ["url", "URL"],
    ["note", "Notes"]
]);

// Protect what is a secret by definition: anything landing in the KDBX
// Password slot (KDBX protects it by convention), anything Buttercup types as
// a password or OTP, and SSH private keys (typed "note" but plainly secret).
function isSecret(property, valueType, kdbxField) {
    return (
        kdbxField === "Password" ||
        valueType === "password" ||
        valueType === "otp" ||
        property === "privateKey"
    );
}

// Buttercup only persists a BC_ENTRY_FIELD_TYPE attribute when the user
// overrides it, so entry.getPropertyValueType() reports "text" for an ordinary
// login password. The facade knows each entry type's real defaults.
function valueTypesFor(entry) {
    const types = new Map();
    try {
        for (const field of createEntryFacade(entry).fields) {
            if (field.propertyType === "property" && field.valueType) {
                types.set(field.property, field.valueType);
            }
        }
    } catch {
        // Unknown/!custom entry type - fall back to the stored attributes.
    }
    return (property) => types.get(property) ?? entry.getPropertyValueType(property);
}

// kdbxweb creates customData lazily; make sure the map exists before writing.
function setCustom(target, key, value) {
    if (!target.customData) target.customData = new Map();
    target.customData.set(key, { value: String(value) });
}

function uniqueFieldName(fields, name) {
    if (!fields.has(name)) return name;
    let n = 2;
    while (fields.has(`${name} (${n})`)) n++;
    return `${name} (${n})`;
}

// Buttercup has no entry timestamps, but format B records a per-field change
// log with timestamps. Earliest/latest of that is the best available answer.
function entryTimes(entry) {
    const stamps = (entry.getChanges() || []).map((c) => c.ts).filter((ts) => Number.isFinite(ts) && ts > 0);
    if (!stamps.length) return null;
    return { created: new Date(Math.min(...stamps)), modified: new Date(Math.max(...stamps)) };
}

async function convertEntry(db, kdbxGroup, entry, attachmentManager) {
    const kentry = db.createEntry(kdbxGroup);
    const properties = entry.getProperty();
    const attributes = entry.getAttribute() || {};

    // Two passes so the mapping never depends on property insertion order:
    // an exactly-named `password` always wins the KDBX Password slot over a
    // custom field that merely differs in case.
    const valueTypeOf = valueTypesFor(entry);
    const all = Object.entries(properties);
    const usedStandard = new Set();
    let otpTaken = false;

    for (const [property, value] of [
        ...all.filter(([p]) => STANDARD.has(p)),
        ...all.filter(([p]) => !STANDARD.has(p))
    ]) {
        const valueType = valueTypeOf(property);

        // OTP -> the `otp` field KeePassXC reads natively.
        if (valueType === "otp") {
            const name = otpTaken ? uniqueFieldName(kentry.fields, `otp_${property}`) : "otp";
            otpTaken = true;
            kentry.fields.set(name, kdbxweb.ProtectedValue.fromString(value));
            continue;
        }

        const mapped = STANDARD.get(property.toLowerCase());
        const kdbxField =
            mapped && !usedStandard.has(mapped)
                ? mapped
                : uniqueFieldName(kentry.fields, property);
        if (mapped && kdbxField === mapped) usedStandard.add(mapped);

        kentry.fields.set(
            kdbxField,
            isSecret(property, valueType, kdbxField)
                ? kdbxweb.ProtectedValue.fromString(value)
                : value
        );
    }

    // Tags: Buttercup's own tags, plus the entry type so it survives as
    // something you can search on.
    const tags = new Set(entry.getTags() || []);
    const type = entry.getType();
    if (type) tags.add(type);
    kentry.tags = [...tags];

    // Every Buttercup attribute is kept verbatim in KDBX entry CustomData —
    // lossless, and out of the way of the visible field list.
    for (const [key, value] of Object.entries(attributes)) {
        setCustom(kentry, key, value);
    }
    setCustom(kentry, "bc_entry_id", entry.id);

    const times = entryTimes(entry);
    if (times) {
        kentry.times.creationTime = times.created;
        kentry.times.lastModTime = times.modified;
        kentry.times.lastAccessTime = times.modified;
    }

    // Attachments -> KDBX binaries.
    if (attachmentManager) {
        for (const key of Object.keys(attributes)) {
            if (!key.startsWith(ATTR.attachmentPrefix)) continue;
            const id = key.slice(ATTR.attachmentPrefix.length);
            const details = await attachmentManager.getAttachmentDetails(entry, id);
            const data = await attachmentManager.getAttachment(entry, id);
            const buffer = data instanceof Buffer ? data : Buffer.from(data);
            const binary = await db.createBinary(new Uint8Array(buffer));
            kentry.binaries.set(uniqueFieldName(kentry.binaries, details?.name || id), binary);
        }
    }

    return kentry;
}

async function convertGroup(db, kdbxParent, group, attachmentManager) {
    const kgroup = db.createGroup(kdbxParent, group.getTitle());
    for (const [key, value] of Object.entries(group.getAttribute() || {})) {
        setCustom(kgroup, key, value);
    }
    setCustom(kgroup, "bc_group_id", group.id);
    for (const entry of group.getEntries()) {
        await convertEntry(db, kgroup, entry, attachmentManager);
    }
    for (const child of group.getGroups()) {
        await convertGroup(db, kgroup, child, attachmentManager);
    }
    return kgroup;
}

/**
 * Build a KDBX4 database from an unlocked Buttercup VaultSource.
 */
export async function vaultToKdbx(source, outPassword, { name, keyfile = null } = {}) {
    installArgon2();
    const vault = source.vault;
    const attachmentManager = source.supportsAttachments() ? source.attachmentManager : null;

    const credentials = new kdbxweb.Credentials(
        kdbxweb.ProtectedValue.fromString(outPassword),
        keyfile
    );
    const db = kdbxweb.Kdbx.create(credentials, name || source.name || "Buttercup");
    db.setVersion(4);
    db.setKdf(kdbxweb.Consts.KdfId.Argon2id);

    for (const [key, value] of Object.entries(vault.getAttribute() || {})) {
        setCustom(db.meta, key, value);
    }

    const root = db.getDefaultGroup();
    const trash = vault.getTrashGroup();
    let recycleBin = null;

    for (const group of vault.getGroups()) {
        if (trash && group.id === trash.id) continue;
        await convertGroup(db, root, group, attachmentManager);
    }

    if (trash) {
        db.createRecycleBin(); // returns void; fetch the group it configured
        recycleBin = db.getGroup(db.meta.recycleBinUuid);
        for (const entry of trash.getEntries()) {
            await convertEntry(db, recycleBin, entry, attachmentManager);
        }
        for (const child of trash.getGroups()) {
            await convertGroup(db, recycleBin, child, attachmentManager);
        }
    }

    return db;
}

// --- Verification --------------------------------------------------------

// Canonical dump of a KDBX db, used to prove the saved file round-trips and
// to compare against the source vault.
export function dumpKdbx(db) {
    const dumpEntry = (e) => ({
        fields: Object.fromEntries(
            [...e.fields.entries()]
                .map(([k, v]) => [k, v instanceof kdbxweb.ProtectedValue ? v.getText() : String(v ?? "")])
                .sort(([a], [b]) => a.localeCompare(b))
        ),
        tags: [...e.tags].sort(),
        customData: Object.fromEntries(
            [...(e.customData ?? new Map()).entries()].map(([k, v]) => [k, v.value]).sort(([a], [b]) => a.localeCompare(b))
        ),
        binaries: [...e.binaries.keys()].sort()
    });
    const dumpGroup = (g) => ({
        name: g.name,
        entries: g.entries.map(dumpEntry).sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b))),
        groups: g.groups.map(dumpGroup).sort((a, b) => a.name.localeCompare(b.name))
    });
    return dumpGroup(db.getDefaultGroup());
}

export function dumpVault(vault) {
    const dumpEntry = (e) => ({ id: e.id, properties: e.getProperty() });
    const dumpGroup = (g) => ({
        title: g.getTitle(),
        entries: g.getEntries().map(dumpEntry).sort((a, b) => a.id.localeCompare(b.id)),
        groups: g.getGroups().map(dumpGroup).sort((a, b) => a.title.localeCompare(b.title))
    });
    return vault.getGroups().map(dumpGroup).sort((a, b) => a.title.localeCompare(b.title));
}

export { kdbxweb };
