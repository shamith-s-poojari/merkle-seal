/*
 * The page: one session (the current seal, and the latest verification against it)
 * shown on the dashboard, and the views that create or check it. The cryptography
 * lives in merkle.js, seal.js and sign.js; the pieces of UI live in ./ui/.
 */

import { isHash } from './merkle.js';
import {
  createSeal, parseSeal, verifySet, parseProofSource, verifyFile, signSeal, FORMAT,
} from './seal.js';
import { checkSignature, shortFingerprint } from './sign.js';
import { createHashPool } from './hash-pool.js';
import {
  $, h, short, plural, basename, bytes, download, copy, errorCard, status, setSlot,
} from './ui/dom.js';
import { dropZone, fromInput } from './ui/files.js';
import { proofCard } from './ui/tree.js';
import { renderLab } from './ui/lab.js';
import { signingPanel, currentSigner, onSignerChange } from './ui/signing.js';
import { renderDashboard, setSearch } from './ui/dashboard.js';
import { icon } from './ui/icons.js';

/* ---------- hashing ---------- */

// Files are hashed on a pool of workers when the browser allows it. Twice as many
// files as workers are kept in flight, so a worker never waits on the main thread.
const pool = createHashPool();
const hashing = pool ? { hashContent: pool.hash, concurrency: pool.size * 2 } : {};
const engine = pool ? plural(pool.size, 'worker') : 'the main thread';
$('engine-chip').replaceChildren(h('span', { class: 'dot' }), `${engine} · offline`);

/** Hash with progress shown in a view's status line. Returns the result and timing. */
async function timed(name, entries, work) {
  const total = entries.reduce((n, e) => n + (e.size ?? 0), 0);
  const started = performance.now();
  try {
    const result = await work({
      ...hashing,
      onProgress: (done, count, bytesDone) =>
        status(name, `Hashing ${done} of ${count} on ${engine}… ${total ? Math.round(100 * bytesDone / total) : 100}%`),
    });
    return { result, ms: performance.now() - started };
  } finally {
    status(name, '');
  }
}

/* ---------- views and navigation ---------- */

const VIEWS = {
  dashboard: ['Dashboard', 'Integrity overview'],
  seal: ['Workflows', 'Seal files'],
  verify: ['Workflows', 'Verify a set'],
  one: ['Workflows', 'Check one file'],
  lab: ['Security', 'Attack lab'],
  key: ['Security', 'Signing key'],
};
let labDrawn = false;

function showView(name) {
  if (!VIEWS[name]) name = 'dashboard';
  for (const v of Object.keys(VIEWS)) $(`view-${v}`).hidden = v !== name;
  for (const a of document.querySelectorAll('.nav [data-view]')) {
    if (a.dataset.view === name) a.setAttribute('aria-current', 'page');
    else a.removeAttribute('aria-current');
  }
  [$('crumb-view').textContent, $('crumb-title').textContent] = VIEWS[name];
  document.title = name === 'dashboard' ? 'Merkle Seal' : `${VIEWS[name][1]} · Merkle Seal`;
  // The lab animates as it draws, so it waits until someone opens it.
  if (name === 'lab' && !labDrawn) { labDrawn = true; renderLab($('lab-out')); }
  setMenu(false);
  if (location.hash.slice(1) !== name) history.replaceState(null, '', `#${name}`);
  scrollTo({ top: 0 });
}

addEventListener('hashchange', () => showView(location.hash.slice(1)));

function setMenu(open) {
  document.body.classList.toggle('menu-open', open);
  $('menu').setAttribute('aria-expanded', String(open));
  $('scrim').hidden = !open;
}
$('menu').addEventListener('click', () => setMenu(!document.body.classList.contains('menu-open')));
$('scrim').addEventListener('click', () => setMenu(false));

$('search').addEventListener('input', (e) => {
  if ($('view-dashboard').hidden) showView('dashboard');
  setSearch(e.target.value);
});
$('top-new').addEventListener('click', () => $('seal-files').click());

/* ---------- the session ---------- */

// manifest: what is shown and downloaded. For a seal made here, that is `base`
// signed with the active key, if there is one. A loaded seal is shown as it came.
let session = null;   // { base, manifest, levels, ms, demo, own, verification }
let renderToken = 0;

async function setSession(next) {
  session = next;
  await refresh();
}

async function refresh() {
  if (!session) return;
  const token = ++renderToken;
  const signer = currentSigner();
  const manifest = session.own && signer ? await signSeal(session.base, signer) : session.base;
  const signature = await checkSignature(manifest);
  if (token !== renderToken) return;
  session.manifest = manifest;

  renderDashboard($('dashboard'), { ...session, engine, signature }, {
    newSeal: () => $('seal-files').click(),
    verifyFiles: pickAndVerify,
    tamperDemo,
    clearVerification: () => setSession({ ...session, verification: null }),
    openView: showView,
  });
  renderSealSummary(manifest, signature);
}

onSignerChange(() => { renderKey(); if (session?.own) refresh(); });

/* ---------- seal ---------- */

dropZone('seal', (entries) => runSeal(entries));
$('demo').addEventListener('click', () => runSeal(demoFiles(), { demo: true }));

async function runSeal(entries, { demo = false, navigate = true } = {}) {
  $('seal-out').replaceChildren();
  if (!entries.length) { status('seal', 'No files found in that drop.'); return; }
  try {
    const { result, ms } = await timed('seal', entries, (opts) => createSeal(entries, opts));
    await setSession({ base: result.manifest, levels: result.levels, ms, demo, own: true, verification: null });
    if (navigate) showView('dashboard');
  } catch (err) {
    showView('seal');
    $('seal-out').replaceChildren(errorCard(err));
  }
}

function renderSealSummary(manifest, signature) {
  const copyBtn = h('button', { class: 'btn', onclick: () => copy(copyBtn, manifest.root) }, icon('copy'), h('span', null, 'Copy root'));
  $('seal-out').replaceChildren(h('div', { class: 'card' },
    h('h2', null, 'Current seal'),
    h('p', { class: 'sub' }, `${plural(manifest.files.length, 'file')} · ${signature.present ? `signed with key ${shortFingerprint(signature.fingerprint)}` : 'unsigned'}`),
    h('div', { class: 'root-hash' }, manifest.root),
    h('div', { class: 'actions' },
      h('button', { class: 'btn btn-solid', onclick: () => download('seal.json', manifest) }, icon('download'),
        h('span', null, manifest.signature ? 'Download signed seal.json' : 'Download seal.json')),
      copyBtn,
      h('button', { class: 'btn', onclick: () => showView('dashboard') }, icon('grid'), h('span', null, 'Open dashboard')),
      !signature.present && h('button', { class: 'btn', onclick: () => showView('key') }, icon('key'), h('span', null, 'Sign seals')))));
}

/* ---------- verify ---------- */

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
  $('verify-out').replaceChildren();
  const { manifest, entries } = verifyState;
  if (!manifest || !entries?.length) {
    status('verify', manifest ? 'Now add the files to check.' : entries ? 'Now add the seal.json to check them against.' : '');
    return;
  }
  try {
    await verifyInto(manifest, entries, 'verify', run);
  } catch (err) {
    if (run === verifyRun) $('verify-out').replaceChildren(errorCard(err));
  }
}

/** Verify `entries` against `manifest`, make that the session and open the dashboard. */
async function verifyInto(manifest, entries, statusName, run = ++verifyRun) {
  const { result, ms } = await timed(statusName, entries, (opts) => verifySet(manifest, entries, opts));
  if (run !== verifyRun) return;
  // Keep our own signed seal as the session when it is the one being checked.
  const same = session && session.manifest.root === result.manifest.root;
  const base = same ? session.base : result.manifest;
  await setSession({
    base, levels: result.levels, ms: same ? session.ms : ms,
    demo: same && session.demo, own: same && session.own,
    verification: { result, ms },
  });
  showView('dashboard');
}

/** "Verify files" on the dashboard: pick files and check them against the current seal. */
function pickAndVerify() {
  const input = h('input', { type: 'file', multiple: true, hidden: true });
  input.addEventListener('change', async () => {
    const entries = fromInput(input);
    input.remove();
    if (!entries.length) return;
    try { await verifyInto(session.manifest, entries, 'dash'); }
    catch (err) { status('dash', err.message); }
  });
  document.body.append(input);
  input.click();
}

/* ---------- check one file ---------- */

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

const signedBy = (sig) => sig.present
  ? sig.valid
    ? h('span', { class: 'match' }, `key ${shortFingerprint(sig.fingerprint)}, signature valid`)
    : h('span', { class: 'mismatch' }, 'signature does not match this root')
  : h('span', { class: 'muted' }, 'not signed');

let oneRun = 0;
async function runOne() {
  const run = ++oneRun;
  const out = $('one-out');
  out.replaceChildren();
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
    out.replaceChildren(
      h('div', { class: `banner ${result.ok && (!sig.present || sig.valid) ? 'ok' : 'bad'}` },
        h('span', { class: 'banner-icon' }, icon(result.ok ? 'shield' : 'alert')),
        h('div', { class: 'banner-text' },
          h('b', null, result.ok ? 'Verified. ' : 'Does not verify. '),
          h('span', null, result.ok
            ? `${file.path} is the file sealed as ${entry.path}, under this root. Checked with ${plural(entry.proof.length, 'sibling hash', 'sibling hashes')} and nothing else from the set.`
            : result.contentHash !== entry.contentHash
              ? `${file.path} is not the file sealed as ${entry.path}: its content hash differs from the sealed one.`
              : 'The file matches the sealed content hash, but its proof does not lead to this root.'),
          h('span', { class: 'banner-meta' }, 'Signed by: ', signedBy(sig),
            !fromProof && ' · checked against the root you entered, not the one in the proof'))),
      await proofCard({ title: 'The check, step by step', path: entry.path, contentHash: result.contentHash, proof: entry.proof, root }));
  } catch (err) {
    if (run !== oneRun) return;
    status('one', '');
    out.replaceChildren(errorCard(err));
  }
}

/* ---------- signing key ---------- */

function renderKey() {
  $('key-out').replaceChildren(
    h('div', { class: 'card' }, h('h2', null, 'Active key'), signingPanel()),
    h('div', { class: 'card' },
      h('h2', null, 'How verifiers use it'),
      h('ol', { class: 'plain-list' },
        h('li', null, 'The signature covers the text ', h('code', null, 'merkle-seal v2 / root / created'), ', so the root and the sealing time cannot change without breaking it.'),
        h('li', null, 'The public key travels inside the seal. Its fingerprint is recomputed from the key during verification, never read from the seal.'),
        h('li', null, 'A valid signature proves which key signed. Publish your fingerprint somewhere people already trust, so they can tell the key is yours.'))));
}
renderKey();

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

async function tamperDemo() {
  const entries = demoFiles({ 'data/report.csv': DEMO['data/report.csv'].replace('135500', '153500') });
  try { await verifyInto(session.manifest, entries, 'dash'); }
  catch (err) { status('dash', err.message); }
}

/* ---------- start ---------- */

// Open on a sealed demo set, so the first thing on screen is the product, not an empty box.
showView(location.hash.slice(1));
runSeal(demoFiles(), { demo: true, navigate: false });
