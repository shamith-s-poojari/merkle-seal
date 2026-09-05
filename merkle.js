/*
 * Merkle tree over a set of files, with domain separation.
 *
 * Leaves and internal nodes are hashed with different prefixes (0x00 / 0x01).
 * Without that, an attacker who can choose file contents could supply a "file"
 * whose bytes happen to equal the concatenation of two real child hashes, and
 * pass it off as an internal node. That is the second-preimage attack on plain
 * Merkle trees, and the prefix is the standard fix (RFC 6962 does the same).
 */

const LEAF = 0x00;
const NODE = 0x01;

/** SHA-256 of an ArrayBuffer, returned as a Uint8Array. */
export async function sha256(bytes) {
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return new Uint8Array(digest);
}

export function toHex(bytes) {
  return [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
}

export function fromHex(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

function concat(prefix, a, b) {
  const out = new Uint8Array(1 + a.length + (b ? b.length : 0));
  out[0] = prefix;
  out.set(a, 1);
  if (b) out.set(b, 1 + a.length);
  return out;
}

/** Hash of one file's contents, tagged as a leaf. */
export async function leafHash(fileBytes) {
  const inner = await sha256(fileBytes);
  return sha256(concat(LEAF, inner));
}

/** Hash of two child nodes, tagged as internal. */
export async function nodeHash(left, right) {
  return sha256(concat(NODE, left, right));
}

/**
 * Build the tree bottom up from leaf hashes.
 *
 * An odd node at any level is promoted unchanged rather than duplicated.
 * Duplicating it is the well known Bitcoin CVE-2012-2459 flaw: two different
 * leaf sets can then produce the same root, so the root stops being a unique
 * commitment to the set.
 *
 * Returns { root, levels } where levels[0] is the leaves.
 */
export async function buildTree(leaves) {
  if (leaves.length === 0) return { root: null, levels: [[]] };

  const levels = [leaves];
  let current = leaves;

  while (current.length > 1) {
    const next = [];
    for (let i = 0; i < current.length; i += 2) {
      if (i + 1 < current.length) {
        next.push(await nodeHash(current[i], current[i + 1]));
      } else {
        next.push(current[i]);          // promoted, not duplicated
      }
    }
    levels.push(next);
    current = next;
  }

  return { root: current[0], levels };
}

/**
 * The sibling hashes needed to recompute the root from leaf `index`.
 * This is what makes the tool able to say *which* file changed rather than
 * only that something did: each leaf carries its own short proof.
 */
export function proofFor(levels, index) {
  const proof = [];
  let idx = index;

  for (let level = 0; level < levels.length - 1; level++) {
    const nodes = levels[level];
    const isRight = idx % 2 === 1;
    const siblingIdx = isRight ? idx - 1 : idx + 1;

    if (siblingIdx < nodes.length) {
      proof.push({ hash: toHex(nodes[siblingIdx]), side: isRight ? 'left' : 'right' });
    }
    // no sibling means this node was promoted; nothing to combine with
    idx = Math.floor(idx / 2);
  }

  return proof;
}

/** Recompute a root from a leaf plus its proof, to check it matches. */
export async function verifyProof(leaf, proof, expectedRoot) {
  let acc = leaf;
  for (const step of proof) {
    const sib = fromHex(step.hash);
    acc = step.side === 'left' ? await nodeHash(sib, acc) : await nodeHash(acc, sib);
  }
  return toHex(acc) === toHex(expectedRoot);
}
