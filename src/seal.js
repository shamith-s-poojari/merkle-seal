/*
 * Seals, proofs and verification on top of the Merkle tree in merkle.js.
 *
 * A seal is a JSON manifest: the root, plus for every file its path, size, content
 * hash, leaf hash and inclusion proof, and optionally a signature over the root.
 * Nothing in this module touches the DOM, so the same code runs in the app and under
 * `node --test`.
 *
 * Files come in as { path, bytes } or { path, size, read() } where read() resolves to
 * an ArrayBuffer, so a large set never has to be in memory all at once.
 */

import {
  sha256, toHex, isHash, normalizePath, comparePaths,
  leafHash, buildTree, proofFor, isProof, foldProof, verifyProof,
} from './merkle.js';
import { isSignature, checkSignature, signRoot } from './sign.js';

export const FORMAT = 'merkle-seal';
export const PROOF_FORMAT = 'merkle-seal-proof';
export const VERSION = 2;

export const SCHEME = Object.freeze({
  hash: 'SHA-256',
  leaf: 'SHA-256(0x00 || u32be(len(path)) || utf8(path) || SHA-256(content))',
  node: 'SHA-256(0x01 || left || right)',
  oddNode: 'promoted unchanged',
  order: 'paths sorted by UTF-8 bytes',
});

export class SealError extends Error {
  constructor(message, problems = []) {
    super(message);
    this.name = 'SealError';
    this.problems = problems;
  }
}

const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;

/** Hash one file's content on this thread. Returns { digest, size }. */
export async function hashInline(entry) {
  const bytes = entry.bytes ?? await entry.read();
  return { digest: await sha256(bytes), size: bytes.byteLength };
}

/**
 * Hash every file and return rows sorted by path:
 * { path, size, contentHash (hex), leaf (bytes) }.
 * Sorting makes the root depend on the set of files, not on the order they arrived.
 *
 * `hashContent(entry)` does the content hashing (the app passes a Web Worker pool),
 * and at most `concurrency` files are in flight at once, which bounds memory.
 * onProgress(done, total, bytesDone) fires as each file finishes.
 */
export async function hashEntries(entries, { onProgress, hashContent = hashInline, concurrency = 4 } = {}) {
  const paths = entries.map(e => normalizePath(e.path));
  const seen = new Set();
  for (const path of paths) {
    if (seen.has(path)) throw new SealError(`"${path}" appears twice. Every file in a seal needs a unique path.`);
    seen.add(path);
  }

  const rows = new Array(entries.length);
  let next = 0, done = 0, bytesDone = 0;
  const lane = async () => {
    while (next < entries.length) {
      const i = next++;
      const { digest, size } = await hashContent(entries[i]);
      rows[i] = { path: paths[i], size, contentHash: toHex(digest), leaf: await leafHash(paths[i], digest) };
      bytesDone += size;
      onProgress?.(++done, entries.length, bytesDone);
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, entries.length) }, lane));
  return rows.sort((a, b) => comparePaths(a.path, b.path));
}

/**
 * Seal a set of files. Returns { manifest, levels }.
 * Pass `signer` ({ privateKey, publicJwk } from sign.js) to sign the root as well.
 */
export async function createSeal(entries, { createdAt = new Date(), signer, ...hashing } = {}) {
  if (!entries.length) throw new SealError('There is nothing to seal. Add at least one file.');
  const rows = await hashEntries(entries, hashing);
  const { root, levels } = await buildTree(rows.map(r => r.leaf));

  const manifest = {
    format: FORMAT,
    version: VERSION,
    scheme: { ...SCHEME },
    createdAt: createdAt.toISOString(),
    root: toHex(root),
    files: rows.map((r, i) => ({
      path: r.path,
      size: r.size,
      contentHash: r.contentHash,
      leafHash: toHex(r.leaf),
      proof: proofFor(levels, i),
    })),
  };
  return { manifest: signer ? await signSeal(manifest, signer) : manifest, levels };
}

/** A copy of the seal with a signature over its root and time. Replaces any old one. */
export async function signSeal(manifest, signer) {
  return { ...manifest, signature: await signRoot(manifest, signer) };
}

/** A copy of the seal without its signature. */
export function unsignSeal(manifest) {
  const { signature, ...rest } = manifest;
  return rest;
}

function parseJson(input, what) {
  if (typeof input !== 'string') return input;
  try { return JSON.parse(input); }
  catch { throw new SealError(`That ${what} is not valid JSON.`); }
}

/**
 * Check a manifest's shape and return a normalised copy (lowercase hashes).
 * This only checks that it is well formed. auditSeal checks that it is consistent.
 */
export function parseSeal(input) {
  const m = parseJson(input, 'seal');
  if (!m || typeof m !== 'object' || Array.isArray(m)) throw new SealError('That file is not a Merkle Seal manifest.');
  if (m.format !== FORMAT) {
    if (m.version === 1 && Array.isArray(m.files)) {
      throw new SealError('This seal was made by an earlier version of Merkle Seal, which did not bind file names into the tree. Seal the files again to get a current manifest.');
    }
    throw new SealError('That file is not a Merkle Seal manifest.');
  }
  if (m.version !== VERSION) throw new SealError(`Unsupported seal version ${m.version}. This build reads version ${VERSION}.`);
  if (!isHash(m.root)) throw new SealError('The seal has no valid root hash.');
  if (!Array.isArray(m.files) || m.files.length === 0) throw new SealError('The seal lists no files.');

  const seen = new Set();
  const files = m.files.map((f, i) => {
    const where = `File ${i + 1} in the seal`;
    if (!f || typeof f.path !== 'string') throw new SealError(`${where} has no path.`);
    let path;
    try { path = normalizePath(f.path); } catch { throw new SealError(`${where} has an empty path.`); }
    if (path !== f.path) throw new SealError(`${where} has a non-canonical path "${f.path}".`);
    if (seen.has(path)) throw new SealError(`"${path}" is listed twice in the seal.`);
    seen.add(path);
    if (!Number.isSafeInteger(f.size) || f.size < 0) throw new SealError(`"${path}" has an invalid size.`);
    if (!isHash(f.contentHash) || !isHash(f.leafHash)) throw new SealError(`"${path}" has an invalid hash.`);
    if (!isProof(f.proof)) throw new SealError(`"${path}" has a malformed inclusion proof.`);
    return {
      path, size: f.size,
      contentHash: f.contentHash.toLowerCase(),
      leafHash: f.leafHash.toLowerCase(),
      proof: f.proof.map(s => ({ side: s.side, hash: s.hash.toLowerCase() })),
    };
  });
  for (let i = 1; i < files.length; i++) {
    if (comparePaths(files[i - 1].path, files[i].path) >= 0) throw new SealError('The files in the seal are not in canonical order.');
  }
  if (m.signature !== undefined && !isSignature(m.signature)) throw new SealError('The seal has a malformed signature.');

  return {
    format: FORMAT, version: VERSION, scheme: { ...SCHEME },
    createdAt: typeof m.createdAt === 'string' ? m.createdAt : null,
    root: m.root.toLowerCase(),
    files,
    ...(m.signature ? { signature: m.signature } : {}),
  };
}

/**
 * Check that a manifest is internally consistent: every leaf hash really is the leaf
 * for its path and content hash, the leaves rebuild the stated root, and every proof
 * reaches that root. A manifest that fails this has been edited by hand, and its
 * per-file hashes cannot be trusted.
 *
 * Returns { ok, problems: [{ path, reason }], levels } where levels is the tree the
 * manifest describes.
 */
export async function auditSeal(manifest) {
  const problems = [];
  const leaves = [];
  for (const f of manifest.files) {
    const leaf = await leafHash(f.path, f.contentHash);
    if (toHex(leaf) !== f.leafHash) problems.push({ path: f.path, reason: 'leaf hash does not match its path and content hash' });
    leaves.push(leaf);
  }
  const { root, levels } = await buildTree(leaves);
  if (toHex(root) !== manifest.root) problems.push({ path: null, reason: 'the files listed do not rebuild the sealed root' });
  for (const [i, f] of manifest.files.entries()) {
    if (!await verifyProof(leaves[i], f.proof, manifest.root)) problems.push({ path: f.path, reason: 'inclusion proof does not reach the sealed root' });
  }
  return { ok: problems.length === 0, problems, levels };
}

/**
 * Verify a set of files against a seal.
 *
 * Each supplied file that the seal names is checked on its own, by hashing it and
 * folding its leaf up through the sealed inclusion proof. Then the whole current set
 * is rebuilt into a tree, and that root is compared with the sealed one.
 *
 * Each result has a status:
 *   unchanged  the file's leaf proves against the sealed root
 *   modified   the file is present but its proof no longer reaches the root
 *   missing    the seal names it but it was not supplied
 *   added      supplied but not in the seal
 *   renamed    an added file whose content matches a missing one
 *
 * A signed seal must carry a valid signature; `signature` in the result says who
 * signed it (as a key fingerprint), or that it was not signed.
 */
export async function verifySet(input, entries, hashing = {}) {
  const manifest = parseSeal(input);
  const audit = await auditSeal(manifest);
  if (!audit.ok) {
    throw new SealError('This seal is internally inconsistent, so it has been edited since it was made. It cannot be used to verify anything.', audit.problems);
  }
  const signature = await checkSignature(manifest);
  if (signature.present && !signature.valid) {
    throw new SealError('This seal is signed, but the signature does not match its root and sealing time. The seal was altered after signing, or the signature was copied from another seal.');
  }

  const rows = await hashEntries(entries, hashing);
  const current = new Map(rows.map(r => [r.path, r]));
  const sealedPaths = new Set(manifest.files.map(f => f.path));

  const results = [];
  for (const [index, f] of manifest.files.entries()) {
    const now = current.get(f.path);
    if (!now) {
      results.push({ path: f.path, status: 'missing', index, sealed: f });
      continue;
    }
    const proves = await verifyProof(now.leaf, f.proof, manifest.root);
    results.push({
      path: f.path, status: proves ? 'unchanged' : 'modified', index,
      sealed: f, size: now.size, contentHash: now.contentHash,
    });
  }

  for (const r of rows) {
    if (sealedPaths.has(r.path)) continue;
    const gone = results.find(x => x.status === 'missing' && x.sealed.contentHash === r.contentHash);
    if (gone) {
      Object.assign(gone, { status: 'renamed', from: gone.path, path: r.path, size: r.size, contentHash: r.contentHash });
    } else {
      results.push({ path: r.path, status: 'added', index: null, size: r.size, contentHash: r.contentHash });
    }
  }

  const { root } = await buildTree(rows.map(r => r.leaf));
  const currentRoot = root ? toHex(root) : null;
  const counts = { unchanged: 0, modified: 0, missing: 0, added: 0, renamed: 0 };
  for (const r of results) counts[r.status]++;

  return {
    manifest,
    intact: currentRoot === manifest.root,
    sealedRoot: manifest.root,
    currentRoot,
    results,
    counts,
    signature,
    levels: audit.levels,
  };
}

/** One-line summary of a verification, e.g. "1 modified, 1 missing". */
export function describeCounts(counts) {
  const parts = ['modified', 'missing', 'added', 'renamed']
    .filter(k => counts[k]).map(k => `${counts[k]} ${k}`);
  return parts.length ? parts.join(', ') : `${plural(counts.unchanged, 'file')} unchanged`;
}

/** A standalone proof for one sealed file, enough to verify that file alone. */
export function proofDocument(manifest, path) {
  const f = manifest.files.find(x => x.path === path);
  if (!f) throw new SealError(`"${path}" is not in this seal.`);
  return {
    format: PROOF_FORMAT, version: VERSION, scheme: { ...SCHEME },
    root: manifest.root,
    createdAt: manifest.createdAt,
    path: f.path, size: f.size, contentHash: f.contentHash, leafHash: f.leafHash,
    proof: f.proof,
    // The signature covers only the root and time, so it carries over to one file.
    ...(manifest.signature ? { signature: manifest.signature } : {}),
  };
}

/**
 * Read either a single-file proof or a whole seal, and return the proofs it holds as
 * [{ path, size, contentHash, leafHash, proof, root, createdAt, signature? }].
 */
export function parseProofSource(input) {
  const doc = parseJson(input, 'proof');
  if (doc && doc.format === FORMAT) {
    const m = parseSeal(doc);
    return m.files.map(f => ({ ...f, root: m.root, createdAt: m.createdAt, signature: m.signature }));
  }
  if (!doc || doc.format !== PROOF_FORMAT) throw new SealError('That file is neither a seal nor a single-file proof.');
  if (doc.version !== VERSION) throw new SealError(`Unsupported proof version ${doc.version}. This build reads version ${VERSION}.`);
  const m = parseSeal({
    format: FORMAT, version: VERSION, root: doc.root, createdAt: doc.createdAt, signature: doc.signature,
    files: [{ path: doc.path, size: doc.size, contentHash: doc.contentHash, leafHash: doc.leafHash, proof: doc.proof }],
  });
  return [{ ...m.files[0], root: m.root, createdAt: m.createdAt, signature: m.signature }];
}

/**
 * Check one file against a root using only its inclusion proof.
 * `entry` is the proof for that file, as returned by parseProofSource. The leaf is
 * computed from the sealed path and the bytes supplied now.
 *
 * Returns { ok, contentHash, trail } where trail is the leaf followed by every
 * intermediate hash up to the root the proof implies.
 */
export async function verifyFile(entry, root, bytes) {
  if (!isHash(root)) throw new SealError('The root must be a 64 character SHA-256 hex digest.');
  const content = await sha256(bytes);
  const trail = await foldProof(await leafHash(entry.path, content), entry.proof);
  return {
    ok: toHex(trail[trail.length - 1]) === root.toLowerCase(),
    contentHash: toHex(content),
    trail: trail.map(toHex),
  };
}
