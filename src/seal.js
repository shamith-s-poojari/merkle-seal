/*
 * Seals, proofs and verification on top of the Merkle tree in merkle.js.
 *
 * A seal is a JSON manifest: the root, plus for every file its path, size, content
 * hash, leaf hash and inclusion proof. Nothing in this module touches the DOM, so the
 * same code runs in the app and under `node --test`.
 *
 * Files come in as { path, bytes } or { path, read() } where read() resolves to an
 * ArrayBuffer, so the app can hash one file at a time instead of loading them all.
 */

import {
  sha256, toHex, isHash, normalizePath, comparePaths,
  leafHash, buildTree, proofFor, isProof, foldProof, verifyProof,
} from './merkle.js';

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

/**
 * Hash every file and return rows sorted by path:
 * { path, size, contentHash (hex), leaf (bytes) }.
 * Sorting makes the root depend on the set of files, not on the order they arrived.
 */
export async function hashEntries(entries, onProgress) {
  const rows = [];
  const seen = new Set();
  let done = 0;
  for (const entry of entries) {
    const path = normalizePath(entry.path);
    if (seen.has(path)) throw new SealError(`"${path}" appears twice. Every file in a seal needs a unique path.`);
    seen.add(path);

    const bytes = entry.bytes ?? await entry.read();
    const content = await sha256(bytes);
    rows.push({ path, size: bytes.byteLength, contentHash: toHex(content), leaf: await leafHash(path, content) });
    onProgress?.(++done, entries.length);
  }
  return rows.sort((a, b) => comparePaths(a.path, b.path));
}

/** Seal a set of files. Returns { manifest, levels }. */
export async function createSeal(entries, { createdAt = new Date(), onProgress } = {}) {
  if (!entries.length) throw new SealError('There is nothing to seal. Add at least one file.');
  const rows = await hashEntries(entries, onProgress);
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
  return { manifest, levels };
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

  return {
    format: FORMAT, version: VERSION, scheme: { ...SCHEME },
    createdAt: typeof m.createdAt === 'string' ? m.createdAt : null,
    root: m.root.toLowerCase(),
    files,
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
 */
export async function verifySet(input, entries, { onProgress } = {}) {
  const manifest = parseSeal(input);
  const audit = await auditSeal(manifest);
  if (!audit.ok) {
    throw new SealError('This seal is internally inconsistent, so it has been edited since it was made. It cannot be used to verify anything.', audit.problems);
  }

  const rows = await hashEntries(entries, onProgress);
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
    path: f.path, size: f.size, contentHash: f.contentHash, leafHash: f.leafHash,
    proof: f.proof,
  };
}

/**
 * Read either a single-file proof or a whole seal, and return the proofs it holds as
 * [{ path, size, contentHash, leafHash, proof, root }].
 */
export function parseProofSource(input) {
  const doc = parseJson(input, 'proof');
  if (doc && doc.format === FORMAT) {
    const m = parseSeal(doc);
    return m.files.map(f => ({ ...f, root: m.root }));
  }
  if (!doc || doc.format !== PROOF_FORMAT) throw new SealError('That file is neither a seal nor a single-file proof.');
  if (doc.version !== VERSION) throw new SealError(`Unsupported proof version ${doc.version}. This build reads version ${VERSION}.`);
  const { files: [f], root } = parseSeal({
    format: FORMAT, version: VERSION, root: doc.root,
    files: [{ path: doc.path, size: doc.size, contentHash: doc.contentHash, leafHash: doc.leafHash, proof: doc.proof }],
  });
  return [{ ...f, root }];
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
