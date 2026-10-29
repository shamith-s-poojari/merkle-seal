# Merkle Seal

Seal a set of files under one Merkle root. Later, check the files against that seal and
find out exactly which file was modified, added, removed or renamed, not just that
"something changed".

**Try it:** <https://shamith-s-poojari.github.io/merkle-seal/> (there is a built-in demo
if you have no files to hand)

Everything runs in the browser. Files are read and hashed locally with the Web Crypto
API, and the page's Content Security Policy sets `connect-src 'none'`, so the page cannot
send anything anywhere even if it wanted to. No server, no upload, no analytics, no
dependencies.

## What it does

| Mode | Input | Output |
|---|---|---|
| **Seal** | files or a folder | the root, a tree view, and a `seal.json` with every file's hash and inclusion proof; each file's proof can also be exported on its own |
| **Verify** | `seal.json` plus the files as they are now | a verdict, and every file marked `unchanged`, `modified`, `missing`, `not in seal` or `renamed`, with the changed paths drawn in red on the tree |
| **One file** | one file, its proof (or the whole seal) and a root you trust | whether that file is the one that was sealed, shown as each hash step from leaf to root |

## How it works

### The tree

```
leaf = SHA-256(0x00 ‖ u32be(len(path)) ‖ utf8(path) ‖ SHA-256(content))
node = SHA-256(0x01 ‖ left ‖ right)
```

Files are sorted by path (UTF-8 byte order) and become the leaves. Pairs are hashed
upwards until one hash is left: the root. Change any byte of any file, or rename it, and
the root changes.

### Why a tree and not a list of hashes

A list of hashes also detects tampering, so the tree has to earn its place. It does two
things a list cannot:

- **One value seals the whole set.** You publish or store 32 bytes, not one hash per file.
- **One file can be proved without the others.** Each file comes with an *inclusion
  proof*: the sibling hashes needed to recompute the root from that one leaf. For 1,000
  files that is 10 hashes instead of 1,000. Certificate Transparency and Bitcoin use the
  same structure for the same reason.

Verification uses those proofs directly. Each file you supply is hashed, and its fresh
leaf is folded up through its sealed proof. If that does not land on the sealed root, that
file is the one that changed.

### Details that are easy to get wrong

**Domain separation.** Leaves and internal nodes are hashed with different prefixes
(`0x00` and `0x01`). Without them, someone who controls a file's bytes could submit a
"file" that is exactly the concatenation of two real child hashes and have it accepted as
an internal node: the second-preimage attack on plain Merkle trees. RFC 6962 uses the same
fix.

**Odd nodes are promoted, not duplicated.** When a level has an odd number of nodes, the
last one moves up unchanged. The common shortcut of hashing it with a copy of itself is
Bitcoin's CVE-2012-2459: `[a, b, c]` and `[a, b, c, c]` then have the same root, so the
root no longer pins down the set.

**The path is inside the leaf.** Hashing only the content would make the root a
commitment to a bag of contents. Binding the path means a proof says "this content is at
this path", so renaming or swapping two files is caught. The path is length-prefixed so its
bytes can never run into the content hash.

**Canonical order and names.** Paths are Unicode NFC with `/` separators and are sorted by
their UTF-8 bytes. `localeCompare` would depend on the browser's locale, and macOS and
Windows can return the same name in different Unicode forms, either of which would give the
same files different roots on different machines.

**A seal checks itself before it is trusted.** Before a seal is used, every leaf hash is recomputed from
its path and content hash, the leaves are rebuilt into the root, and every proof is
checked. A hand-edited `seal.json` is refused with a list of what does not add up, instead
of reporting doctored hashes as "unchanged".

## The seal format

```json
{
  "format": "merkle-seal",
  "version": 2,
  "scheme": { "hash": "SHA-256", "leaf": "...", "node": "...", "oddNode": "promoted unchanged", "order": "..." },
  "createdAt": "2026-10-29T12:00:00.000Z",
  "root": "ed576adf…",
  "files": [
    {
      "path": "data/report.csv",
      "size": 70,
      "contentHash": "3460b1d4…",
      "leafHash": "6ddc2648…",
      "proof": [
        { "side": "left", "hash": "c5068345…" },
        { "side": "left", "hash": "b381d652…" },
        { "side": "right", "hash": "fb2b0bcf…" }
      ]
    }
  ]
}
```

`contentHash` is a plain SHA-256 of the file, so it can be checked with `sha256sum`.
`side` says which side the sibling sits on when it is combined with the running hash. A
single-file proof (`*.proof.json`) holds the same fields for one file plus the root, with
`"format": "merkle-seal-proof"`.

## Project layout

```
index.html        the page
styles.css
src/merkle.js     hashing, tree building, inclusion proofs (no DOM)
src/seal.js       sealing, seal parsing and auditing, set and single-file verification (no DOM)
src/app.js        UI: drag and drop, folder walking, tree drawing, proof steps
test/cases.js     test cases shared by both runners
test/run.test.js  runs them under Node
tests.html        runs them in the browser
```

`merkle.js` and `seal.js` use only the standard Web Crypto API, so the same code runs in
the browser and in Node without changes.

## Running it locally

`crypto.subtle` needs a secure context, which `file://` is not, so serve the folder:

```bash
npx serve .
```

## Tests

```bash
npm test
```

27 cases, no dependencies (Node 20 or newer). They cover the SHA-256 test vector, the
exact leaf and node byte layouts, domain separation, path binding and normalisation, byte
order sorting, proofs for every leaf of every tree size from 1 to 33, rejection of forged
leaves, flipped sides and altered siblings, the CVE-2012-2459 case, order independence,
detection of modified, missing, added and renamed files, refusal of a hand-edited seal,
malformed input, and single-file verification against the right and wrong roots.

The same cases run in the browser at [`tests.html`](https://shamith-s-poojari.github.io/merkle-seal/tests.html),
against that browser's own Web Crypto implementation.

## Deploying

The site is static, so GitHub Pages serves it as is: Settings → Pages → Deploy from a
branch → `main`, folder `/ (root)`. `.nojekyll` stops Jekyll from processing the files.

## Known limits

- Each file is read fully into memory before hashing, so very large files are slow. Web
  Crypto has no streaming SHA-256, so incremental hashing would need a hand-written one.
- The seal is not signed. It proves the files match what was sealed; it does not prove
  who sealed them. Anyone who can change both the files and the seal can make them agree,
  so keep the root (or the seal) somewhere the files cannot reach, or publish the root.
- `createdAt` comes from the sealer's clock. It is a note, not evidence.
- `.DS_Store`, `Thumbs.db` and `desktop.ini` are skipped, since copying a folder between
  machines adds or changes them.

## Licence

MIT
