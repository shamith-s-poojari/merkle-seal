# Merkle Seal

Hash a set of files into a single Merkle root, then check later whether any of them
changed. If one did, it names the file rather than just saying the set is broken.

**Live:** <https://shamith-s-poojari.github.io/merkle-seal/>

Everything runs in the browser. Files are read and hashed locally with the Web Crypto
API. There is no server, no upload, and no analytics.

## Why a tree instead of a list of hashes

A list of hashes already detects tampering, so the tree has to earn its place. It does
two things a list cannot:

- **One value seals the whole set.** You publish or store 32 bytes, not one hash per
  file. Change any byte of any file and the root changes.
- **A single file can be proved without the others.** Each file ships with an
  *inclusion proof*: the handful of sibling hashes needed to recompute the root from
  that one leaf. For a 1000 file set that is about 10 hashes instead of 1000. This is
  the same structure Certificate Transparency and Bitcoin use, for the same reason.

## Two details that are easy to get wrong

**Domain separation.** Leaves are hashed as `SHA-256(0x00 ‖ SHA-256(file))` and internal
nodes as `SHA-256(0x01 ‖ left ‖ right)`. Without the different prefixes, an attacker who
controls file contents could submit a "file" whose bytes are exactly the concatenation
of two real child hashes and have it accepted as an internal node. That is the
second-preimage attack on plain Merkle trees; RFC 6962 uses the same fix.

**Odd nodes are promoted, not duplicated.** When a level has an odd number of nodes, the
last one moves up unchanged. The common shortcut is to duplicate it and hash it with
itself, which is the Bitcoin flaw CVE-2012-2459: two different sets of leaves can then
produce the same root, so the root stops uniquely committing to the set. There is a test
covering this.

## Using it

**Seal.** Drop files in. You get a root hash and a `seal.json` holding each file's hash
and its inclusion proof. Keep that file somewhere the data itself cannot reach.

**Verify.** Drop `seal.json` back in along with the files. You get one of:

| Result | Meaning |
|---|---|
| `unchanged` | hash matches the sealed value |
| `changed` | file exists but its contents differ |
| `missing` | sealed file was not supplied |
| `not sealed` | file supplied that was not in the original set |

Files are sorted by name before hashing, so the root depends on the set and not on the
order they were dropped.

## Running it

Needs a secure context, because `crypto.subtle` is unavailable on `file://`. Any static
server works:

```bash
npx serve .
```

Then open the localhost URL it prints.

## Tests

`tests.html` runs the tree logic in the browser and prints pass or fail. It covers
determinism, tamper detection, proof verification for every leaf, rejection of a forged
leaf, the odd-node collision case, domain separation, and the single-file and empty-set
edges.

## Known limits

- Each file is read fully into memory before hashing, so very large files will be slow.
  Incremental hashing would need a streaming SHA-256, which the Web Crypto API does not
  expose.
- The manifest is not signed. It proves the files have not changed since sealing; it
  does not prove who sealed them. Signing it would be the natural next step.
- Timestamps come from the local clock, so they are a note to yourself, not evidence.

## Licence

MIT
