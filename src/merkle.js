/*
 * Merkle tree over a set of named files, with domain separation.
 *
 *   leaf = SHA-256(0x00 ‖ u32be(len(path)) ‖ utf8(path) ‖ SHA-256(content))
 *   node = SHA-256(0x01 ‖ left ‖ right)
 *
 * Leaves and internal nodes use different prefixes. Without that, an attacker who
 * can choose a file's bytes could supply a "file" equal to the concatenation of two
 * real child hashes and pass it off as an internal node: the second-preimage attack
 * on plain Merkle trees. RFC 6962 (Certificate Transparency) uses the same fix.
 *
 * The path is part of the leaf, so the root commits to which content sits under
 * which name, not only to a bag of contents. The length prefix stops one path's
 * bytes from bleeding into the content hash.
 *
 * Everything here uses only Web Crypto, so it runs unchanged in browsers and Node.
 */

const LEAF = 0x00;
const NODE = 0x01;
const utf8 = new TextEncoder();

/** SHA-256 of some bytes, as a Uint8Array. */
export async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

export function toHex(bytes) {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

export function fromHex(hex) {
  if (typeof hex !== 'string' || !/^(?:[0-9a-fA-F]{2})*$/.test(hex)) {
    throw new TypeError(`not a hex string: ${String(hex).slice(0, 20)}`);
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** True for a lowercase or uppercase 64 character SHA-256 hex digest. */
export const isHash = (hex) => typeof hex === 'string' && /^[0-9a-fA-F]{64}$/.test(hex);

const bytesOf = (h) => (typeof h === 'string' ? fromHex(h) : h);

/**
 * Canonical form of a file path: Unicode NFC, forward slashes, no leading "./" or "/".
 * NFC matters because macOS and Windows can hand back the same name in different
 * normal forms, which would otherwise change the leaf.
 */
export function normalizePath(path) {
  const clean = String(path).normalize('NFC').replace(/\\/g, '/')
    .split('/').filter(s => s !== '' && s !== '.').join('/');
  if (!clean) throw new TypeError('empty file path');
  return clean;
}

/**
 * Order paths by their UTF-8 bytes. localeCompare would depend on the browser's
 * locale, so the same files could seal to different roots on different machines.
 */
export function comparePaths(a, b) {
  const x = utf8.encode(a), y = utf8.encode(b);
  const n = Math.min(x.length, y.length);
  for (let i = 0; i < n; i++) if (x[i] !== y[i]) return x[i] - y[i];
  return x.length - y.length;
}

/** Leaf hash binding a path to the SHA-256 of that file's content. */
export async function leafHash(path, contentHash) {
  const name = utf8.encode(path);
  const content = bytesOf(contentHash);
  if (content.length !== 32) throw new TypeError('content hash must be 32 bytes');

  const buf = new Uint8Array(1 + 4 + name.length + 32);
  buf[0] = LEAF;
  new DataView(buf.buffer).setUint32(1, name.length);
  buf.set(name, 5);
  buf.set(content, 5 + name.length);
  return sha256(buf);
}

/** Hash of two child nodes, tagged as internal. */
export async function nodeHash(left, right) {
  const buf = new Uint8Array(1 + 64);
  buf[0] = NODE;
  buf.set(left, 1);
  buf.set(right, 33);
  return sha256(buf);
}

/**
 * Build the tree bottom up from leaf hashes.
 *
 * An odd node at the end of a level is promoted unchanged rather than paired with
 * a copy of itself. Duplicating it is Bitcoin's CVE-2012-2459: [a, b, c] and
 * [a, b, c, c] then share a root, so the root stops being a unique commitment.
 *
 * Returns { root, levels } where levels[0] is the leaves and the last level is [root].
 */
export async function buildTree(leaves) {
  if (leaves.length === 0) return { root: null, levels: [[]] };

  const levels = [leaves];
  let current = leaves;
  while (current.length > 1) {
    const next = [];
    for (let i = 0; i < current.length; i += 2) {
      next.push(i + 1 < current.length ? await nodeHash(current[i], current[i + 1]) : current[i]);
    }
    levels.push(next);
    current = next;
  }
  return { root: current[0], levels };
}

/** Index of the node on each level that lies on the path from leaf `index` to the root. */
export function pathIndices(levels, index) {
  return levels.map((_, level) => index >> level);
}

/**
 * The sibling hashes needed to recompute the root from leaf `index`, lowest first.
 * `side` says which side the sibling sits on. A level where the node was promoted
 * has no sibling and contributes no step.
 */
export function proofFor(levels, index) {
  if (!Number.isInteger(index) || index < 0 || index >= levels[0].length) {
    throw new RangeError(`no leaf at index ${index}`);
  }
  const proof = [];
  let idx = index;
  for (let level = 0; level < levels.length - 1; level++) {
    const isRight = idx % 2 === 1;
    const sibling = isRight ? idx - 1 : idx + 1;
    if (sibling < levels[level].length) {
      proof.push({ side: isRight ? 'left' : 'right', hash: toHex(levels[level][sibling]) });
    }
    idx >>= 1;
  }
  return proof;
}

/** True if `proof` is a well formed list of { side, hash } steps. */
export function isProof(proof) {
  return Array.isArray(proof) && proof.length <= 64 &&
    proof.every(s => s && (s.side === 'left' || s.side === 'right') && isHash(s.hash));
}

/**
 * Fold a leaf up through its proof. Returns every intermediate hash, starting with
 * the leaf itself and ending with the root the proof implies.
 */
export async function foldProof(leaf, proof) {
  if (!isProof(proof)) throw new TypeError('malformed inclusion proof');
  const trail = [bytesOf(leaf)];
  let acc = trail[0];
  for (const step of proof) {
    const sib = fromHex(step.hash);
    acc = step.side === 'left' ? await nodeHash(sib, acc) : await nodeHash(acc, sib);
    trail.push(acc);
  }
  return trail;
}

/** Recompute a root from a leaf plus its proof and compare it with `expectedRoot`. */
export async function verifyProof(leaf, proof, expectedRoot) {
  if (!isProof(proof)) return false;
  const trail = await foldProof(leaf, proof);
  return toHex(trail[trail.length - 1]) === toHex(bytesOf(expectedRoot));
}
