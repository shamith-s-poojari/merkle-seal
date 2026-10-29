/*
 * The two classic attacks on Merkle trees, run for real against a deliberately
 * weakened tree and against the one this project uses. The attack lab on the page
 * and the tests both call these, so the claims in the README are checked, not asserted.
 *
 * Nothing in here is used for sealing. The weakened builders exist only to show
 * what the defences in merkle.js are defending against.
 */

import { sha256, toHex, leafHash, nodeHash, buildTree } from './merkle.js';

const utf8 = new TextEncoder();

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
}

/** A tree with no domain separation: leaf = H(content), node = H(left ‖ right). */
async function untaggedTree(leaves) {
  const levels = [leaves];
  let current = leaves;
  while (current.length > 1) {
    const next = [];
    for (let i = 0; i < current.length; i += 2) {
      next.push(i + 1 < current.length ? await sha256(concat(current[i], current[i + 1])) : current[i]);
    }
    levels.push(next);
    current = next;
  }
  return { root: current[0], levels };
}

/** The real node hash, but an odd node is paired with a copy of itself (Bitcoin's rule). */
async function duplicatingTree(leaves) {
  const levels = [leaves];
  let current = leaves;
  while (current.length > 1) {
    const next = [];
    for (let i = 0; i < current.length; i += 2) {
      next.push(await nodeHash(current[i], current[i + 1] ?? current[i]));
    }
    levels.push(next);
    current = next;
  }
  return { root: current[0], levels };
}

export const LAB_FILES = [
  { path: 'contract.txt', text: 'Payment of 1,000 due on 1 November.' },
  { path: 'invoice.txt', text: 'Invoice 0042: 1,000.' },
  { path: 'receipt.txt', text: 'Received with thanks.' },
  { path: 'terms.txt', text: 'Net 30 days.' },
];

/**
 * Second preimage. The attacker never touches the sealed files. Instead they present
 * a different, smaller set: two "files" whose bytes are the concatenated hashes of
 * the real leaves. Without domain separation those files hash to the real internal
 * nodes, so the fake set has the same root as the genuine one.
 */
export async function secondPreimageAttack({ domainSeparation }) {
  const contents = LAB_FILES.map(f => utf8.encode(f.text));
  const leafOf = domainSeparation
    ? async (path, bytes) => leafHash(path, await sha256(bytes))
    : async (_path, bytes) => sha256(bytes);
  const tree = domainSeparation ? buildTree : untaggedTree;

  const leaves = await Promise.all(LAB_FILES.map((f, i) => leafOf(f.path, contents[i])));
  const genuine = await tree(leaves);

  // Each forged file is literally two real leaf hashes glued together.
  const forged = [
    { path: 'fake-1.bin', bytes: concat(leaves[0], leaves[1]) },
    { path: 'fake-2.bin', bytes: concat(leaves[2], leaves[3]) },
  ];
  const fake = await tree(await Promise.all(forged.map(f => leafOf(f.path, f.bytes))));

  return {
    genuine: { names: LAB_FILES.map(f => f.path), ...genuine },
    fake: { names: forged.map(f => f.path), ...fake },
    forged: forged.map(f => ({ path: f.path, hex: toHex(f.bytes) })),
    collides: toHex(genuine.root) === toHex(fake.root),
  };
}

/**
 * CVE-2012-2459. With three leaves, duplicating the odd one out builds exactly the
 * same tree as a four-leaf list that repeats it. So [a, b, c] and [a, b, c, c] share
 * a root, and the root no longer says which set was sealed. Promoting the odd node
 * instead keeps them apart.
 */
export async function duplicateOddAttack({ promote }) {
  const three = LAB_FILES.slice(0, 3);
  const leaves = await Promise.all(three.map(async f => leafHash(f.path, await sha256(utf8.encode(f.text)))));
  const tree = promote ? buildTree : duplicatingTree;

  const genuine = await tree(leaves);
  const fake = await tree([...leaves, leaves[2]]);
  return {
    genuine: { names: three.map(f => f.path), ...genuine },
    fake: { names: [...three.map(f => f.path), three[2].path], ...fake },
    collides: toHex(genuine.root) === toHex(fake.root),
  };
}
