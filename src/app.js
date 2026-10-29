/*
 * The page: wiring the four panes together. The cryptography lives in merkle.js,
 * seal.js and sign.js; the pieces of UI live in ./ui/.
 */

import { isHash, pathIndices } from './merkle.js';
import {
  createSeal, parseSeal, verifySet, describeCounts, proofDocument,
  parseProofSource, verifyFile, signSeal, FORMAT,
} from './seal.js';
import { checkSignature, shortFingerprint } from './sign.js';
import { createHashPool } from './hash-pool.js';
import {
  $, h, short, plural, basename, bytes, duration, download, copy, errorCard, status, setSlot,
} from './ui/dom.js';
import { dropZone } from './ui/files.js';
import { treeCard, proofCard, proofMarks } from './ui/tree.js';
import { renderLab } from './ui/lab.js';
import { signingPanel, currentSigner, onSignerChange } from './ui/signing.js';

/* ---------- hashing ---------- */

// Files are hashed on a pool of workers when the browser allows it. Twice as many
// files as workers are kept in flight, so a worker never waits on the main thread.
const pool = createHashPool();
const hashing = pool ? { hashContent: pool.hash, concurrency: pool.size * 2 } : {};
const engine = pool ? `${plural(pool.size, 'worker')}` : 'the main thread';

/** Hash with progress shown in a pane's status line. Returns the result and timing. */
async function timed(name, entries, work) {
  const total = entries.reduce((n, e) => n + (e.size ?? 0), 0);
  const started = performance.now();
  const result = await work({
    ...hashing,
    onProgress: (done, count, bytesDone) =>
      status(name, `Hashing ${done} of ${count} on ${engine}… ${total ? Math.round(100 * bytesDone / total) : 100}%`),
  });
  status(name, '');
  return { result, ms: performance.now() - started };
}

/* ---------- tabs ---------- */

const tabs = ['seal', 'verify', 'one', 'lab'];
let labDrawn = false;

function showTab(name, focus = false) {
  for (const t of tabs) {
    const tab = $(`tab-${t}`);
    tab.setAttribute('aria-selected', String(t === name));
    tab.tabIndex = t === name ? 0 : -1;
    $(`pane-${t}`).hidden = t !== name;
  }
  // The lab animates as it draws, so it waits until someone opens it.
  if (name === 'lab' && !labDrawn) { labDrawn = true; renderLab($('lab-out')); }
  if (focus) $(`tab-${name}`).focus();
}

for (const [i, t] of tabs.entries()) {
  const tab = $(`tab-${t}`);
  tab.addEventListener('click', () => showTab(t));
  tab.addEventListener('keydown', (e) => {
    const step = e.key === 'ArrowRight' ? 1 : e.key === 'ArrowLeft' ? -1 : 0;
    if (step) showTab(tabs[(i + step + tabs.length) % tabs.length], true);
  });
}

/* ---------- 1. seal ---------- */

const sealOut = $('seal-out');
let sealed = null;   // { manifest (unsigned), levels, ms, demo }

dropZone('seal', (entries) => runSeal(entries));
$('demo').addEventListener('click', () => runSeal(demoFiles(), { demo: true }));
onSignerChange(() => { if (sealed) renderSeal(); });

async function runSeal(entries, { demo = false } = {}) {
  sealOut.replaceChildren();
  if (!entries.length) { status('seal', 'No files found in that drop.'); return; }
  try {
    const { result, ms } = await timed('seal', entries, (opts) => createSeal(entries, opts));
    sealed = { ...result, ms, demo };
    await renderSeal({ animate: true });
  } catch (err) {
    status('seal', '');
    sealOut.replaceChildren(errorCard(err));
  }
}

function statsStrip(manifest, levels, ms) {
  const n = manifest.files.length;
  const total = manifest.files.reduce((sum, f) => sum + f.size, 0);
  const proof = manifest.files.reduce((sum, f) => sum + f.proof.length, 0) / n;
  const rate = total / Math.max(ms, 1) * 1000;
  const tile = (value, label) => h('div', { class: 'stat' }, h('b', null, value), h('span', null, label));
  return h('div', { class: 'stats' },
    tile(n.toLocaleString('en'), n === 1 ? 'file' : 'files'),
    tile(bytes(total), 'hashed'),
    tile(duration(ms), `on ${engine}`),
    // On a few bytes the time is all start-up, so a rate would only mislead.
    total >= 1048576 && tile(`${bytes(rate)}/s`, 'throughput'),
    tile(String(levels.length), 'tree levels'),
    tile(`${Number(proof.toFixed(1))} × 32 B`, `proof per file, vs ${n.toLocaleString('en')} × 32 B for a hash list`));
}

async function renderSeal({ animate = false } = {}) {
  const { levels, ms, demo } = sealed;
  const signer = currentSigner();
  const manifest = signer ? await signSeal(sealed.manifest, signer) : sealed.manifest;
  const names = manifest.files.map(f => f.path);

  const copyBtn = h('button', { class: 'btn', onclick: () => copy(copyBtn, manifest.root) }, 'copy root');
  const head = h('div', { class: 'card' },
    h('h2', null, demo ? 'Sealed: demo set' : 'Sealed'),
    h('p', { class: 'sub' }, demo
      ? 'Six sample files, sealed in this browser just now. Drop your own files above to seal them instead.'
      : `Hashed in this browser. Nothing was uploaded.`),
    h('div', { class: 'root-hash' }, manifest.root),
    statsStrip(manifest, levels, ms),
    signingPanel(),
    h('div', { class: 'actions' },
      h('button', { class: 'btn solid', onclick: () => download('seal.json', manifest) },
        manifest.signature ? 'download signed seal.json' : 'download seal.json'),
      copyBtn,
      h('button', { class: 'btn', onclick: () => { loadVerifySeal(manifest, 'this seal'); showTab('verify'); } }, 'verify against this seal')));

  const hint = demo && h('div', { class: 'card hint' },
    h('h2', null, 'Now tamper with it'),
    h('p', null, 'Change one number in one file and verify the whole set against this seal:'),
    h('div', { class: 'actions' },
      h('button', { class: 'btn solid', onclick: () => runDemoVerify(manifest) }, 'edit data/report.csv and verify'),
      h('button', { class: 'btn', onclick: () => showTab('lab', true) }, 'or try to forge a root')));

  const split = h('div', { class: 'split' });
  const rows = new Map();
  const select = async (i, first = false) => {
    for (const [j, tr] of rows) tr.classList.toggle('selected', j === i);
    const f = manifest.files[i];
    split.replaceChildren(
      treeCard(levels, names, { marks: proofMarks(levels, i), onPick: select, animate: first && animate }),
      await proofCard({ title: 'Inclusion proof', path: f.path, contentHash: f.contentHash, proof: f.proof, root: manifest.root }));
  };

  const table = h('div', { class: 'table-wrap' }, h('table', null,
    h('thead', null, h('tr', null, h('th', null, 'path'), h('th', null, 'size'), h('th', null, 'content sha-256'), h('th', null, 'proof'), h('th'))),
    h('tbody', null, manifest.files.map((f, i) => {
      const tr = h('tr', { onclick: () => select(i) },
        h('td', { class: 'path' }, f.path),
        h('td', { class: 'num' }, bytes(f.size)),
        h('td', { class: 'h', title: f.contentHash }, short(f.contentHash)),
        h('td', { class: 'num' }, plural(f.proof.length, 'hash', 'hashes')),
        h('td', { class: 'act' }, h('button', {
          class: 'btn small', title: `Download the inclusion proof for ${f.path}`,
          onclick: (e) => { e.stopPropagation(); download(`${basename(f.path)}.proof.json`, proofDocument(manifest, f.path)); },
        }, 'proof.json')));
      rows.set(i, tr);
      return tr;
    }))));

  sealOut.replaceChildren(head, hint || '', split, table);
  await select(0, true);
}

/* ---------- 2. verify a set ---------- */

const verifyOut = $('verify-out');
const verifyState = { manifest: null, entries: null };

dropZone('verify-seal', async (entries) => {
  const [first] = entries;
  if (!first) return;
  try { loadVerifySeal(parseSeal(await first.file.text()), first.path); }
  catch (err) { setSlot('verify-seal', err.message, 'bad'); verifyState.manifest = null; }
});

dropZone('verify-files', async (entries) => {
  // A seal dropped in with the files becomes the seal. Sets often hold JSON files
  // of their own, so only a file that really is a Merkle Seal manifest is taken out.
  let seal = null;
  for (const e of entries.filter(e => e.path.endsWith('.json'))) {
    try {
      const m = JSON.parse(await e.file.text());
      if (m?.format === FORMAT) { seal = { entry: e, manifest: m }; break; }
    } catch { /* not a seal, so it is one of the files */ }
  }
  const files = seal ? entries.filter(x => x !== seal.entry) : entries;
  verifyState.entries = files;
  setSlot('verify-files', files.length ? `${plural(files.length, 'file')} ready` : 'no files in that drop', files.length ? 'ok' : 'bad');
  if (!seal) return runVerify();
  try { loadVerifySeal(parseSeal(seal.manifest), seal.entry.path); }
  catch (err) { verifyState.manifest = null; setSlot('verify-seal', err.message, 'bad'); runVerify(); }
});

function loadVerifySeal(manifest, label) {
  verifyState.manifest = manifest;
  setSlot('verify-seal', `${label}: ${plural(manifest.files.length, 'file')}, root ${short(manifest.root)}${manifest.signature ? ', signed' : ''}`, 'ok');
  runVerify();
}

// Each run is numbered, so a slow earlier run cannot overwrite a newer result.
let verifyRun = 0;
async function runVerify() {
  const run = ++verifyRun;
  verifyOut.replaceChildren();
  const { manifest, entries } = verifyState;
  if (!manifest || !entries?.length) {
    status('verify', manifest ? 'Now add the files to check.' : entries ? 'Now add the seal.json to check them against.' : '');
    return;
  }
  try {
    const { result, ms } = await timed('verify', entries, (opts) => verifySet(manifest, entries, opts));
    if (run !== verifyRun) return;
    await renderVerify(result, ms);
  } catch (err) {
    if (run !== verifyRun) return;
    status('verify', '');
    verifyOut.replaceChildren(errorCard(err));
  }
}

const ORDER = { modified: 0, missing: 1, renamed: 2, added: 3, unchanged: 4 };
const LABEL = { unchanged: 'unchanged', modified: 'modified', missing: 'missing', added: 'not in seal', renamed: 'renamed' };

const signedBy = (sig) => sig.present
  ? h('span', { class: 'match' }, `key ${shortFingerprint(sig.fingerprint)}, signature valid`)
  : h('span', { class: 'sub' }, 'not signed');

async function renderVerify(v, ms) {
  const { manifest, levels, results, intact } = v;
  const bad = results.filter(r => r.status !== 'unchanged');
  const hashedBytes = results.reduce((n, r) => n + (r.contentHash ? r.size : 0), 0);

  const verdict = h('div', { class: `card verdict ${intact ? 'ok' : 'bad'}` },
    h('h2', null, intact ? 'Intact' : 'Changed'),
    h('p', null, intact
      ? `All ${plural(results.length, 'file')} match the seal, and the rebuilt root equals the sealed root.`
      : `${describeCounts(v.counts)}. ${bad.length === 1 ? 'This file is' : 'These files are'} why the root no longer matches:`),
    !intact && h('ul', null, bad.sort((a, b) => ORDER[a.status] - ORDER[b.status]).map(r =>
      h('li', null, r.status === 'renamed' ? `${r.from} → ${r.path} (renamed, content unchanged)` : `${r.path} (${LABEL[r.status]})`))),
    h('dl', { class: 'kv' },
      h('dt', null, 'sealed root'), h('dd', { class: 'hash' }, v.sealedRoot),
      h('dt', null, 'root now'), h('dd', { class: intact ? 'match' : 'mismatch' }, v.currentRoot ?? 'no files'),
      h('dt', null, 'signed by'), h('dd', null, signedBy(v.signature)),
      manifest.createdAt && [h('dt', null, 'sealed at'), h('dd', null, `${manifest.createdAt} (sealer's clock${v.signature.present ? ', covered by the signature' : ''})`)],
      h('dt', null, 'checked'), h('dd', null, `${bytes(hashedBytes)} in ${duration(ms)} on ${engine}`)));

  // Changed leaves, and every node above them, turn red on the sealed tree.
  const dirty = new Map();
  for (const r of results) {
    if (r.index === null || r.status === 'unchanged') continue;
    for (const [l, j] of pathIndices(levels, r.index).entries()) dirty.set(`${l}:${j}`, 'dirty');
    if (r.status !== 'modified') dirty.set(`0:${r.index}`, 'gone');
  }
  const names = manifest.files.map(f => f.path);
  const byIndex = new Map(results.filter(r => r.index !== null).map(r => [r.index, r]));

  const split = h('div', { class: 'split' });
  const rows = new Map();
  const select = async (i, first = false) => {
    for (const [j, tr] of rows) tr.classList.toggle('selected', j === i);
    const r = byIndex.get(i);
    const f = manifest.files[i];
    // Damage outranks selection, so a changed path stays red while it is selected.
    const marks = new Map([...proofMarks(levels, i), ...dirty]);
    const present = r.status === 'unchanged' || r.status === 'modified';
    split.replaceChildren(
      treeCard(levels, names, {
        marks, onPick: select, animate: first,
        legend: [h('span', null, h('i', { class: 'dirty' }), 'changed, missing or renamed')],
      }),
      await proofCard({
        title: present ? 'Proof, using the file as it is now' : 'Sealed proof',
        path: f.path,
        contentHash: present ? r.contentHash : f.contentHash,
        proof: f.proof,
        root: manifest.root,
        note: present ? null : r.status === 'renamed'
          ? `This file now lives at ${r.path}. A leaf includes its path, so it no longer proves under the old one.`
          : 'This file was not supplied, so this is the proof as sealed.',
      }));
  };

  const sorted = [...results].sort((a, b) => ORDER[a.status] - ORDER[b.status]);
  const table = h('div', { class: 'table-wrap' }, h('table', null,
    h('thead', null, h('tr', null, h('th', null, 'status'), h('th', null, 'path'), h('th', null, 'size'), h('th', null, 'sealed sha-256'), h('th', null, 'sha-256 now'))),
    h('tbody', null, sorted.map(r => {
      const tr = h('tr', r.index === null ? null : { onclick: () => select(r.index) },
        h('td', null, h('span', { class: `pill ${r.status}` }, LABEL[r.status])),
        h('td', { class: 'path' }, r.path, r.from && h('span', { class: 'from' }, `was ${r.from}`)),
        h('td', { class: 'num' }, bytes(r.size ?? r.sealed.size)),
        h('td', { class: 'h' }, r.sealed ? short(r.sealed.contentHash) : '—'),
        h('td', { class: `h ${r.status === 'modified' ? 'mismatch' : ''}` }, r.contentHash ? short(r.contentHash) : '—'));
      if (r.index !== null) rows.set(r.index, tr);
      return tr;
    }))));

  verifyOut.replaceChildren(verdict, split, table);
  const first = sorted.find(r => r.index !== null);
  if (first) await select(first.index, true);
}

/* ---------- 3. check one file ---------- */

const oneOut = $('one-out');
const oneState = { sources: null, file: null };
const rootInput = $('one-root');
const pick = $('one-pick');

dropZone('one-proof', async (entries) => {
  const [first] = entries;
  if (!first) return;
  try {
    oneState.sources = parseProofSource(await first.file.text());
    const n = oneState.sources.length;
    setSlot('one-proof', n === 1 ? `proof for ${oneState.sources[0].path}` : `seal with ${plural(n, 'file')}`, 'ok');
    rootInput.value = oneState.sources[0].root;
    pick.replaceChildren(...oneState.sources.map((src, i) => h('option', { value: i }, src.path)));
    $('one-pick-wrap').hidden = n === 1;
    matchPick();
  } catch (err) {
    oneState.sources = null;
    setSlot('one-proof', err.message, 'bad');
  }
  runOne();
});

dropZone('one-file', (entries) => {
  if (!entries.length) return;
  oneState.file = entries[0];
  setSlot('one-file', `${oneState.file.path}, ${bytes(oneState.file.size)}${entries.length > 1 ? ' (only the first file is used)' : ''}`, 'ok');
  matchPick();
  runOne();
});

/** When the proof source is a whole seal, pick the entry that matches the file's name. */
function matchPick() {
  const { sources, file } = oneState;
  if (!sources || !file || sources.length === 1) return;
  const exact = sources.findIndex(src => src.path === file.path);
  const byName = sources.map((src, i) => basename(src.path) === basename(file.path) ? i : -1).filter(i => i >= 0);
  const i = exact >= 0 ? exact : byName.length === 1 ? byName[0] : -1;
  if (i >= 0) pick.value = String(i);
}

pick.addEventListener('change', runOne);
rootInput.addEventListener('input', runOne);

let oneRun = 0;
async function runOne() {
  const run = ++oneRun;
  oneOut.replaceChildren();
  const { sources, file } = oneState;
  const root = rootInput.value.trim().toLowerCase();
  rootInput.classList.toggle('bad', root !== '' && !isHash(root));
  if (!sources || !file) {
    status('one', sources ? 'Now add the file to check.' : file ? 'Now add its proof or the seal.' : '');
    return;
  }
  if (!isHash(root)) { status('one', 'The root must be 64 hex characters.'); return; }

  const entry = sources[Number(pick.value) || 0];
  try {
    status('one', 'Hashing…');
    const result = await verifyFile(entry, root, await file.read());
    const sig = await checkSignature(entry);
    if (run !== oneRun) return;
    status('one', '');
    const fromProof = root === entry.root;
    oneOut.replaceChildren(
      h('div', { class: `card verdict ${result.ok && (!sig.present || sig.valid) ? 'ok' : 'bad'}` },
        h('h2', null, result.ok ? 'Verified' : 'Does not verify'),
        h('p', null, result.ok
          ? `${file.path} is the file sealed as ${entry.path}, under this root. Checked with ${plural(entry.proof.length, 'sibling hash', 'sibling hashes')} and nothing else from the set.`
          : result.contentHash !== entry.contentHash
            ? `${file.path} is not the file sealed as ${entry.path}: its content hash differs from the sealed one.`
            : `The file matches the sealed content hash, but its proof does not lead to this root.`),
        !fromProof && h('p', { class: 'sub' }, 'Checked against the root you entered, not the one stored in the proof.'),
        h('dl', { class: 'kv' },
          h('dt', null, 'signed by'),
          h('dd', null, sig.present && !sig.valid
            ? h('span', { class: 'mismatch' }, 'signature does not match this proof’s root')
            : signedBy(sig)))),
      await proofCard({ title: 'The check, step by step', path: entry.path, contentHash: result.contentHash, proof: entry.proof, root }));
  } catch (err) {
    if (run !== oneRun) return;
    status('one', '');
    oneOut.replaceChildren(errorCard(err));
  }
}

/* ---------- demo ---------- */

const DEMO = {
  'README.md': '# Quarterly report\n\nFigures for the board pack. Do not edit after sign-off.\n',
  'LICENSE': 'MIT License\n\nCopyright (c) 2026\n',
  'data/report.csv': 'quarter,revenue,costs\nQ1,120000,84000\nQ2,135500,90250\nQ3,141200,93800\n',
  'data/customers.csv': 'id,name,country\n1,Acme,IN\n2,Globex,US\n3,Initech,DE\n',
  'src/summarise.py': 'import csv\n\nwith open("data/report.csv") as f:\n    rows = list(csv.DictReader(f))\nprint(sum(int(r["revenue"]) for r in rows))\n',
  'signoff.txt': 'Approved by finance, 2026-10-01.\n',
};

const enc = new TextEncoder();
function demoFiles(overrides = {}) {
  return Object.entries({ ...DEMO, ...overrides }).map(([path, text]) => {
    const data = enc.encode(text);
    return { path, size: data.length, read: async () => data };
  });
}

function runDemoVerify(manifest) {
  verifyState.entries = demoFiles({ 'data/report.csv': DEMO['data/report.csv'].replace('135500', '153500') });
  setSlot('verify-files', 'demo files, with Q2 revenue in data/report.csv changed from 135500 to 153500', 'ok');
  loadVerifySeal(manifest, 'demo seal');
  showTab('verify');
}

// Open on a sealed demo set, so the first thing on screen is the tree, not an empty box.
runSeal(demoFiles(), { demo: true });
