/*
 * Test cases for the tree and the seal logic.
 *
 * They are plain async functions with no test framework, so the same file runs
 * under `node --test` (test/run.test.js) and in the browser (tests.html), against
 * each runtime's own Web Crypto implementation.
 */

import {
  sha256, toHex, fromHex, normalizePath, comparePaths,
  leafHash, nodeHash, buildTree, proofFor, foldProof, verifyProof,
} from '../src/merkle.js';
import {
  createSeal, parseSeal, auditSeal, verifySet, proofDocument, hashEntries, hashInline,
  parseProofSource, verifyFile, describeCounts, signSeal, unsignSeal, SealError,
} from '../src/seal.js';
import {
  generateSigningKey, exportSigningKey, importSigningKey, checkSignature, fingerprint,
} from '../src/sign.js';
import { secondPreimageAttack, duplicateOddAttack } from '../src/attacks.js';

class AssertionError extends Error {}

function ok(value, message) {
  if (!value) throw new AssertionError(message);
}

function equal(actual, expected, message) {
  if (actual !== expected) throw new AssertionError(`${message}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
}

async function rejects(fn, pattern, message) {
  try { await fn(); }
  catch (err) {
    if (pattern && !pattern.test(err.message)) throw new AssertionError(`${message}: wrong error "${err.message}"`);
    return err;
  }
  throw new AssertionError(`${message}: expected an error`);
}

const enc = new TextEncoder();
const file = (path, text) => ({ path, bytes: enc.encode(text) });
const leafOf = async (path, text) => leafHash(path, await sha256(enc.encode(text)));
const leaves = (...names) => Promise.all(names.map(n => leafOf(n, `content of ${n}`)));
const hex = (bytes) => toHex(bytes);

const FIXED = new Date('2026-01-01T00:00:00Z');
const SET = [
  file('README.md', '# project\n'),
  file('src/main.c', 'int main(void) { return 0; }\n'),
  file('src/util.c', 'int add(int a, int b) { return a + b; }\n'),
  file('data/report.csv', 'quarter,revenue\nQ1,100\nQ2,120\n'),
  file('LICENSE', 'MIT\n'),
];

export const cases = [];
const test = (name, fn) => cases.push({ name, fn });

/* ---------------- hashing ---------------- */

test('SHA-256 matches the published test vector for "abc"', async () => {
  equal(hex(await sha256(enc.encode('abc'))),
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', 'digest');
});

test('leaf hash is SHA-256(0x00 || u32be(len) || path || SHA-256(content))', async () => {
  const content = await sha256(enc.encode('hello'));
  const path = enc.encode('a.txt');
  const manual = new Uint8Array([0x00, 0, 0, 0, path.length, ...path, ...content]);
  equal(hex(await leafHash('a.txt', content)), hex(await sha256(manual)), 'leaf');
});

test('node hash is SHA-256(0x01 || left || right)', async () => {
  const [l, r] = await leaves('a', 'b');
  equal(hex(await nodeHash(l, r)), hex(await sha256(new Uint8Array([0x01, ...l, ...r]))), 'node');
});

test('leaves and nodes are domain separated', async () => {
  // The same 64 bytes hashed as a node and as a raw digest must differ, so a crafted
  // file can never stand in for an internal node.
  const [l, r] = await leaves('a', 'b');
  const raw = await sha256(new Uint8Array([...l, ...r]));
  ok(hex(await nodeHash(l, r)) !== hex(raw), 'node hash equals an untagged hash');
  const content = await sha256(enc.encode('x'));
  ok(hex(await leafHash('x', content)) !== hex(content), 'leaf hash equals the bare content hash');
});

test('the path is bound into the leaf', async () => {
  const content = await sha256(enc.encode('same bytes'));
  ok(hex(await leafHash('a.txt', content)) !== hex(await leafHash('b.txt', content)), 'renaming kept the leaf');
});

test('hex round-trips and rejects junk', async () => {
  const bytes = new Uint8Array([0, 1, 127, 128, 255]);
  equal(hex(fromHex(hex(bytes))), hex(bytes), 'round trip');
  await rejects(() => fromHex('abc'), /hex/, 'odd length');
  await rejects(() => fromHex('zz'), /hex/, 'non-hex');
});

test('paths are normalised to NFC with forward slashes', async () => {
  equal(normalizePath('.\\docs\\a.txt'), 'docs/a.txt', 'windows path');
  equal(normalizePath('/a//b/./c'), 'a/b/c', 'redundant separators');
  equal(normalizePath('café.txt'), 'café.txt', 'NFD to NFC');
  await rejects(() => normalizePath('/'), /empty/, 'empty path');
});

test('paths sort by UTF-8 bytes, not by locale', async () => {
  const sorted = ['b', 'B', 'a', 'é', 'Z', 'a/b', 'a.b'].sort(comparePaths);
  equal(sorted.join(' '), 'B Z a a.b a/b b é', 'byte order');
});

/* ---------------- tree ---------------- */

test('root is deterministic', async () => {
  const a = await buildTree(await leaves('a', 'b', 'c', 'd'));
  const b = await buildTree(await leaves('a', 'b', 'c', 'd'));
  equal(hex(a.root), hex(b.root), 'root');
});

test('changing one leaf changes the root', async () => {
  const base = await leaves('a', 'b', 'c', 'd');
  const edited = [...base];
  edited[3] = await leafOf('d', 'tampered');
  ok(hex((await buildTree(base)).root) !== hex((await buildTree(edited)).root), 'root unchanged');
});

test('every leaf verifies via its inclusion proof, for 1 to 33 leaves', async () => {
  for (let n = 1; n <= 33; n++) {
    const ls = await leaves(...Array.from({ length: n }, (_, i) => `f${i}`));
    const { root, levels } = await buildTree(ls);
    for (let i = 0; i < n; i++) {
      ok(await verifyProof(ls[i], proofFor(levels, i), root), `leaf ${i} of ${n} failed`);
      ok(proofFor(levels, i).length <= Math.ceil(Math.log2(n)), `proof for leaf ${i} of ${n} is too long`);
    }
  }
});

test('a proof does not verify a different leaf', async () => {
  const ls = await leaves('a', 'b', 'c', 'd');
  const { root, levels } = await buildTree(ls);
  ok(!await verifyProof(await leafOf('x', 'forged'), proofFor(levels, 0), root), 'forged leaf accepted');
  ok(!await verifyProof(ls[1], proofFor(levels, 0), root), 'leaf 1 accepted with the proof for leaf 0');
});

test('a proof with a flipped side or altered sibling is rejected', async () => {
  const ls = await leaves('a', 'b', 'c', 'd');
  const { root, levels } = await buildTree(ls);
  const proof = proofFor(levels, 2);
  const flipped = proof.map((s, i) => i === 0 ? { ...s, side: s.side === 'left' ? 'right' : 'left' } : s);
  ok(!await verifyProof(ls[2], flipped, root), 'flipped side accepted');
  const altered = proof.map((s, i) => i === 1 ? { ...s, hash: '0'.repeat(64) } : s);
  ok(!await verifyProof(ls[2], altered, root), 'altered sibling accepted');
  ok(!await verifyProof(ls[2], [{ side: 'up', hash: 'x' }], root), 'malformed proof accepted');
});

test('an odd node is promoted, not duplicated (CVE-2012-2459)', async () => {
  const three = await leaves('a', 'b', 'c');
  const odd = await buildTree(three);
  const dup = await buildTree([...three, three[2]]);
  ok(hex(odd.root) !== hex(dup.root), 'three leaves and three-plus-a-repeat share a root');
  equal(hex(odd.levels[1][1]), hex(three[2]), 'promoted node');
  equal(proofFor(odd.levels, 2).length, 1, 'promoted leaf proof length');
});

test('a single leaf is its own root and an empty set has none', async () => {
  const [solo] = await leaves('solo');
  const t = await buildTree([solo]);
  equal(hex(t.root), hex(solo), 'single root');
  equal(proofFor(t.levels, 0).length, 0, 'single proof');
  equal((await buildTree([])).root, null, 'empty root');
});

test('foldProof returns the leaf, each step and the root', async () => {
  const ls = await leaves('a', 'b', 'c', 'd', 'e');
  const { root, levels } = await buildTree(ls);
  const trail = await foldProof(ls[4], proofFor(levels, 4));
  equal(hex(trail[0]), hex(ls[4]), 'first');
  equal(hex(trail[trail.length - 1]), hex(root), 'last');
});

/* ---------------- seals ---------------- */

test('a seal does not depend on the order files arrive in', async () => {
  const a = await createSeal(SET, { createdAt: FIXED });
  const b = await createSeal([...SET].reverse(), { createdAt: FIXED });
  equal(a.manifest.root, b.manifest.root, 'root');
  equal(JSON.stringify(a.manifest), JSON.stringify(b.manifest), 'manifest');
});

test('a fresh seal passes its own audit and survives a JSON round trip', async () => {
  const { manifest } = await createSeal(SET, { createdAt: FIXED });
  const parsed = parseSeal(JSON.stringify(manifest));
  ok((await auditSeal(parsed)).ok, 'audit failed');
  equal(parsed.files.length, SET.length, 'file count');
});

test('sealing rejects duplicate paths and an empty set', async () => {
  await rejects(() => createSeal([file('a.txt', '1'), file('./a.txt', '2')]), /twice/, 'duplicate');
  await rejects(() => createSeal([]), /nothing to seal/i, 'empty');
});

test('verifying the untouched set reports it intact', async () => {
  const { manifest } = await createSeal(SET);
  const v = await verifySet(manifest, SET);
  ok(v.intact, 'not intact');
  equal(v.currentRoot, v.sealedRoot, 'roots');
  ok(v.results.every(r => r.status === 'unchanged'), 'some file not unchanged');
  equal(describeCounts(v.counts), '5 files unchanged', 'summary');
});

test('verifying names the one file that changed', async () => {
  const { manifest } = await createSeal(SET);
  const edited = SET.map(f => f.path === 'src/util.c' ? file(f.path, 'int add(int a, int b) { return a - b; }\n') : f);
  const v = await verifySet(manifest, edited);
  ok(!v.intact, 'reported intact');
  const changed = v.results.filter(r => r.status !== 'unchanged');
  equal(changed.length, 1, 'number flagged');
  equal(changed[0].path, 'src/util.c', 'flagged file');
  equal(changed[0].status, 'modified', 'status');
});

test('verifying reports missing, added and renamed files', async () => {
  const { manifest } = await createSeal(SET);
  const now = SET
    .filter(f => f.path !== 'LICENSE')
    .map(f => f.path === 'README.md' ? { ...f, path: 'README.txt' } : f)
    .concat(file('extra.txt', 'not sealed'));
  const v = await verifySet(manifest, now);
  const by = Object.fromEntries(v.results.map(r => [r.path, r]));
  equal(by.LICENSE.status, 'missing', 'LICENSE');
  equal(by['extra.txt'].status, 'added', 'extra.txt');
  equal(by['README.txt'].status, 'renamed', 'README.txt');
  equal(by['README.txt'].from, 'README.md', 'renamed from');
  equal(describeCounts(v.counts), '1 missing, 1 added, 1 renamed', 'summary');
  ok(!v.intact, 'reported intact');
});

test('a hand-edited seal is refused instead of trusted', async () => {
  const { manifest } = await createSeal(SET);
  const evil = await createSeal(SET.map(f => f.path === 'LICENSE' ? file('LICENSE', 'GPL\n') : f));
  // Swap in the tampered file's hashes but keep the original root.
  const forged = structuredClone(manifest);
  const i = forged.files.findIndex(f => f.path === 'LICENSE');
  forged.files[i] = structuredClone(evil.manifest.files[i]);
  const err = await rejects(() => verifySet(forged, SET), /internally inconsistent/, 'forged seal');
  ok(err instanceof SealError && err.problems.length > 0, 'no problems listed');
});

test('malformed or foreign JSON is rejected with a clear message', async () => {
  await rejects(() => parseSeal('{not json'), /not valid JSON/, 'bad json');
  await rejects(() => parseSeal({ name: 'package.json' }), /not a Merkle Seal/, 'foreign json');
  await rejects(() => parseSeal({ version: 1, files: [] }), /earlier version/, 'v1 seal');
  const { manifest } = await createSeal(SET);
  await rejects(() => parseSeal({ ...manifest, root: 'abc' }), /root/, 'bad root');
  await rejects(() => parseSeal({ ...manifest, files: [...manifest.files].reverse() }), /canonical order/, 'unsorted');
});

/* ---------------- single-file proofs ---------------- */

test('one file verifies against the root with only its proof', async () => {
  const { manifest } = await createSeal(SET);
  const doc = JSON.parse(JSON.stringify(proofDocument(manifest, 'src/main.c')));
  const [entry] = parseProofSource(doc);
  const good = await verifyFile(entry, manifest.root, enc.encode('int main(void) { return 0; }\n'));
  ok(good.ok, 'genuine file rejected');
  equal(good.trail[good.trail.length - 1], manifest.root, 'trail ends at root');
  const bad = await verifyFile(entry, manifest.root, enc.encode('int main(void) { return 1; }\n'));
  ok(!bad.ok, 'edited file accepted');
});

test('a single-file proof fails against a different root', async () => {
  const { manifest } = await createSeal(SET);
  const [entry] = parseProofSource(proofDocument(manifest, 'LICENSE'));
  ok(!(await verifyFile(entry, 'f'.repeat(64), enc.encode('MIT\n'))).ok, 'wrong root accepted');
  await rejects(() => verifyFile(entry, 'nope', enc.encode('MIT\n')), /64 character/, 'malformed root');
});

test('a whole seal can serve as the proof source', async () => {
  const { manifest } = await createSeal(SET);
  const entries = parseProofSource(JSON.stringify(manifest));
  equal(entries.length, SET.length, 'entries');
  ok(entries.every(e => e.root === manifest.root), 'root carried');
});

/* ---------------- concurrent hashing ---------------- */

test('hashing keeps at most `concurrency` files in flight and still sorts', async () => {
  let inFlight = 0, peak = 0;
  const slow = async (entry) => {
    peak = Math.max(peak, ++inFlight);
    await new Promise(r => setTimeout(r, 2));
    const out = await hashInline(entry);
    inFlight--;
    return out;
  };
  const many = Array.from({ length: 20 }, (_, i) => file(`f${String(19 - i).padStart(2, '0')}.txt`, `file ${i}`));
  const seen = [];
  const rows = await hashEntries(many, { hashContent: slow, concurrency: 3, onProgress: (d, t, b) => seen.push([d, t, b]) });
  equal(peak, 3, 'peak concurrency');
  equal(rows.map(r => r.path).join(), [...rows.map(r => r.path)].sort(comparePaths).join(), 'sorted');
  equal(seen.length, 20, 'progress calls');
  equal(seen[19][2], many.reduce((n, f) => n + f.bytes.length, 0), 'bytes counted');
});

test('the root does not depend on how many files are hashed in parallel', async () => {
  const a = await createSeal(SET, { createdAt: FIXED, concurrency: 1 });
  const b = await createSeal(SET, { createdAt: FIXED, concurrency: 8 });
  equal(a.manifest.root, b.manifest.root, 'root');
});

/* ---------------- signatures ---------------- */

test('a signed seal verifies and names its signer by fingerprint', async () => {
  const signer = await generateSigningKey();
  const { manifest } = await createSeal(SET, { signer });
  const parsed = parseSeal(JSON.stringify(manifest));
  const sig = await checkSignature(parsed);
  ok(sig.present && sig.valid, 'signature not valid');
  equal(sig.fingerprint, await fingerprint(signer.publicJwk), 'fingerprint');
  const v = await verifySet(parsed, SET);
  ok(v.intact && v.signature.valid, 'verifySet did not accept the signed seal');
});

test('changing the root or time of a signed seal breaks the signature', async () => {
  const signer = await generateSigningKey();
  const { manifest } = await createSeal(SET, { signer, createdAt: FIXED });
  ok(!(await checkSignature({ ...manifest, createdAt: '2027-01-01T00:00:00.000Z' })).valid, 'backdated seal accepted');
  ok(!(await checkSignature({ ...manifest, root: 'a'.repeat(64) })).valid, 'other root accepted');
});

test('a signature lifted onto a different seal is refused', async () => {
  const signer = await generateSigningKey();
  const signed = (await createSeal(SET, { signer })).manifest;
  const other = (await createSeal(SET.slice(1))).manifest;
  await rejects(() => verifySet({ ...other, signature: signed.signature }, SET.slice(1)), /signature does not match/, 'lifted signature');
});

test('a mislabelled key fingerprint is caught', async () => {
  const signer = await generateSigningKey();
  const { manifest } = await createSeal(SET, { signer });
  const lie = { ...manifest, signature: { ...manifest.signature, fingerprint: 'b'.repeat(64) } };
  ok(!(await checkSignature(lie)).valid, 'wrong fingerprint accepted');
});

test('a signing key survives export and import', async () => {
  const first = await generateSigningKey();
  const again = await importSigningKey(JSON.parse(JSON.stringify(await exportSigningKey(first))));
  const { manifest } = await createSeal(SET, { signer: again });
  equal((await checkSignature(manifest)).fingerprint, await fingerprint(first.publicJwk), 'same key');
  await rejects(() => importSigningKey({ kty: 'EC', crv: 'P-256', x: 'a', y: 'b' }), /private key/, 'public-only key');
});

test('signing and unsigning do not change the root', async () => {
  const { manifest } = await createSeal(SET);
  const signed = await signSeal(manifest, await generateSigningKey());
  equal(signed.root, manifest.root, 'root');
  equal(unsignSeal(signed).signature, undefined, 'unsigned');
  equal((await checkSignature(manifest)).present, false, 'unsigned seal has no signature');
});

test('a single-file proof carries the seal signature', async () => {
  const { manifest } = await createSeal(SET, { signer: await generateSigningKey() });
  const [entry] = parseProofSource(JSON.stringify(proofDocument(manifest, 'LICENSE')));
  ok((await checkSignature(entry)).valid, 'proof signature invalid');
});

/* ---------------- attack lab ---------------- */

test('second preimage: works without domain separation, fails with it', async () => {
  const naive = await secondPreimageAttack({ domainSeparation: false });
  ok(naive.collides, 'attack failed against the untagged tree');
  equal(naive.fake.names.length, 2, 'forged set size');
  equal(naive.forged[0].hex.length, 128, 'forged file is two hashes');
  ok(!(await secondPreimageAttack({ domainSeparation: true })).collides, 'attack worked against the real tree');
});

test('CVE-2012-2459: works when odd nodes are duplicated, fails when promoted', async () => {
  ok((await duplicateOddAttack({ promote: false })).collides, 'attack failed against the duplicating tree');
  ok(!(await duplicateOddAttack({ promote: true })).collides, 'attack worked against the real tree');
});
