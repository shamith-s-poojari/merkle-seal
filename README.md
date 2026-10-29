# Merkle Seal

Seal a set of files under one Merkle root, optionally signed. Later, check the files
against that seal and find out exactly which file was modified, added, removed or renamed,
not just that "something changed".

**Try it:** <https://shamith-s-poojari.github.io/merkle-seal/> (it opens on a sealed demo
set, so there is something to verify and tamper with straight away)

Everything runs in the browser. Files are hashed locally with the Web Crypto API on a pool
of Web Workers, and the page's Content Security Policy sets `connect-src 'none'`, so the
page cannot send anything anywhere even if it wanted to. No server, no upload, no
analytics, no dependencies.

## What it does

| Mode | Input | Output |
|---|---|---|
| **Seal** | files or a folder | the root, timing and proof-size stats, a tree view, and a `seal.json` with every file's hash and inclusion proof, optionally signed with ECDSA P-256; each file's proof can also be exported on its own |
| **Verify** | `seal.json` plus the files as they are now | a verdict, every file marked `unchanged`, `modified`, `missing`, `not in seal` or `renamed`, the changed paths drawn in red on the tree, and who signed the seal |
| **One file** | one file, its proof (or the whole seal) and a root you trust | whether that file is the one that was sealed, shown as each hash step from leaf to root, plus the signature check |
| **Attack lab** | nothing | the two classic Merkle forgeries run live, against a weakened tree and against this one, with the defence switchable |

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

### The attack lab

The two defences above are easy to claim, so the page lets anyone watch them work.
[`src/attacks.js`](src/attacks.js) builds deliberately weakened trees and runs each attack
for real:

- **Second preimage.** Against a tree with no prefixes, two 64-byte "files" made of
  concatenated real leaf hashes rebuild the genuine root. With domain separation the same
  forgery gives a different root.
- **CVE-2012-2459.** Against a tree that duplicates odd nodes, `[a, b, c]` and
  `[a, b, c, c]` share a root. With promotion they do not.

The tests run both attacks in both modes, so the lab cannot quietly drift from the claims.

### Signed seals

A root proves the files have not changed since sealing, but not who sealed them: anyone who
can rewrite both the files and the seal can make them agree. A seal can therefore be signed
with ECDSA P-256 over SHA-256 ([`src/sign.js`](src/sign.js)). The signature covers this exact
text, so other tools can reproduce it:

```
merkle-seal v2
root <root hex>
created <createdAt>
```

The root already commits to every file, so signing it signs the whole set, and covering
`createdAt` stops a seal being backdated. The public key travels in the seal; what makes a
signature mean something is its **fingerprint**, the SHA-256 of the raw public key, which a
verifier compares with one they already know. The fingerprint is recomputed from the key
during verification, never read from the seal. Keys are generated in the page, can be saved
as a JWK and loaded again, and never leave the tab otherwise.

### Hashing off the main thread

Content hashing runs on a pool of Web Workers ([`src/hash-pool.js`](src/hash-pool.js)), one
per core up to eight. Each worker reads its `File` itself, so large files never pass through
the page's memory, and the page stays responsive. Twice as many files as workers are kept in
flight, which keeps the workers busy while bounding memory. The result is identical to
hashing on one thread, and a test checks that. In Chrome on an 8-core machine, 100 MB
across 20 files sealed in under 0.1 s.

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
  ],
  "signature": {
    "alg": "ECDSA-P256-SHA256",
    "publicKey": { "kty": "EC", "crv": "P-256", "x": "…", "y": "…" },
    "fingerprint": "23e45a66a8ac3883…",
    "value": "<64-byte r ‖ s, hex>"
  }
}
```

`contentHash` is a plain SHA-256 of the file, so it can be checked with `sha256sum`.
`side` says which side the sibling sits on when it is combined with the running hash.
`signature` is optional. A single-file proof (`*.proof.json`) holds the same fields for one
file plus the root, time and signature, with `"format": "merkle-seal-proof"`.

## Project layout

```
index.html           the page
styles.css
src/merkle.js        hashing, tree building, inclusion proofs
src/seal.js          sealing, seal parsing and auditing, set and single-file verification
src/sign.js          ECDSA P-256 keys, signing and signature checks
src/attacks.js       the weakened trees and the two attacks, for the lab and the tests
src/hash-pool.js     Web Worker pool for content hashing
src/hash-worker.js   the worker
src/app.js           wires the four panes together
src/ui/              DOM helpers, file drops, tree drawing, attack lab, signing panel
test/cases.js        test cases shared by both runners
test/run.test.js     runs them under Node
tests.html           runs them in the browser
```

Everything outside `src/ui/`, `app.js` and the worker pool is free of the DOM and uses only
the standard Web Crypto API, so the same code runs in the browser and in Node unchanged.

## Running it locally

`crypto.subtle` needs a secure context, which `file://` is not, so serve the folder:

```bash
npx serve .
```

## Tests

```bash
npm test
```

38 cases, no dependencies (Node 20 or newer). They cover:

- **Hashing:** the SHA-256 test vector, the exact leaf and node byte layouts, domain
  separation, path binding and normalisation, byte-order sorting.
- **Trees and proofs:** proofs for every leaf of every tree size from 1 to 33; rejection of
  forged leaves, flipped sides and altered siblings; the CVE-2012-2459 case.
- **Seals:** order independence, detection of modified, missing, added and renamed files,
  refusal of a hand-edited seal, malformed input, and single-file checks against the right
  and wrong roots.
- **Signatures:** valid signatures, a changed root or backdated time, a signature lifted
  onto another seal, a mislabelled fingerprint, and key export and import.
- **Concurrency:** the in-flight limit is respected, and the root does not depend on it.
- **The attack lab:** each attack succeeds against the weakened tree and fails against the
  real one.

The same cases run in the browser at [`tests.html`](https://shamith-s-poojari.github.io/merkle-seal/tests.html),
against that browser's own Web Crypto implementation.

## Deploying

The site is static, so GitHub Pages serves it as is: Settings → Pages → Deploy from a
branch → `main`, folder `/ (root)`. `.nojekyll` stops Jekyll from processing the files.

## Known limits

- Each file is read whole inside its worker before hashing. Web Crypto has no streaming
  SHA-256, so a single file larger than the browser's memory allowance cannot be sealed.
- A signature proves which key signed, not whose key it is. Publish your fingerprint
  somewhere people already trust, or keep the root itself out of the files' reach.
- `createdAt` comes from the sealer's clock. A signature stops it being changed later, but
  it is not a trusted timestamp.
- `.DS_Store`, `Thumbs.db` and `desktop.ini` are skipped, since copying a folder between
  machines adds or changes them.

## Licence

MIT
