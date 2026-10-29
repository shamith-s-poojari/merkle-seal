/*
 * The page: reading dropped files, and drawing seals, verifications and proofs.
 * All the cryptography lives in merkle.js and seal.js.
 */

import { toHex, isHash, leafHash, foldProof, pathIndices } from './merkle.js';
import {
  createSeal, parseSeal, verifySet, describeCounts, proofDocument,
  parseProofSource, verifyFile, SealError, FORMAT,
} from './seal.js';

/* ---------- small DOM helpers ---------- */

const $ = (id) => document.getElementById(id);
const SVG = 'http://www.w3.org/2000/svg';

function build(el, attrs, kids) {
  for (const [k, v] of Object.entries(attrs ?? {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.setAttribute('class', v);
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid != null && kid !== false) el.append(kid instanceof Node ? kid : String(kid));
  }
  return el;
}
const h = (tag, attrs, ...kids) => build(document.createElement(tag), attrs, kids);
const s = (tag, attrs, ...kids) => build(document.createElementNS(SVG, tag), attrs, kids);

const short = (hex) => hex.slice(0, 10) + '…';
const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
const basename = (path) => path.slice(path.lastIndexOf('/') + 1);
function bytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1048576).toFixed(1)} MB`;
}

function download(name, data) {
  const blob = new Blob([JSON.stringify(data, null, 2) + '\n'], { type: 'application/json' });
  const a = h('a', { href: URL.createObjectURL(blob), download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

async function copy(button, text) {
  const label = button.textContent;
  try { await navigator.clipboard.writeText(text); button.textContent = 'copied'; }
  catch { button.textContent = 'copy failed'; }
  setTimeout(() => { button.textContent = label; }, 1400);
}

function errorCard(err) {
  const problems = err instanceof SealError ? err.problems : [];
  return h('div', { class: 'card verdict bad', role: 'alert' },
    h('h2', null, err instanceof SealError ? 'Cannot use that' : 'Something went wrong'),
    h('p', null, err.message),
    problems.length > 0 && h('ul', null, problems.map(p => h('li', null, p.path ? `${p.path}: ${p.reason}` : p.reason))));
}

/* ---------- reading files ---------- */

// Operating system clutter that would otherwise make a copied folder look tampered with.
const IGNORED = new Set(['.DS_Store', 'Thumbs.db', 'desktop.ini']);

const entryFor = (path, file) => ({ path, size: file.size, file, read: () => file.arrayBuffer() });
const keep = (list) => list.filter(e => !IGNORED.has(basename(e.path)));

/** Files from an <input>. A folder pick is made relative to the folder itself. */
function fromInput(input) {
  return keep([...input.files].map(f => {
    const rel = f.webkitRelativePath;
    return entryFor(rel ? rel.split('/').slice(1).join('/') : f.name, f);
  }));
}

/**
 * Files from a drop, walking into folders. Dropping one folder gives paths relative
 * to that folder, so sealing "project/" and verifying a renamed copy still lines up.
 */
async function fromDrop(dt) {
  const roots = [...dt.items].filter(i => i.kind === 'file').map(i => i.webkitGetAsEntry?.()).filter(Boolean);
  if (!roots.length) return keep([...dt.files].map(f => entryFor(f.name, f)));

  const found = [];
  const walk = async (entry) => {
    if (entry.isFile) {
      const file = await new Promise((res, rej) => entry.file(res, rej));
      found.push({ path: entry.fullPath.replace(/^\/+/, ''), file });
      return;
    }
    const reader = entry.createReader();
    for (;;) {
      const batch = await new Promise((res, rej) => reader.readEntries(res, rej));
      if (!batch.length) break;
      for (const child of batch) await walk(child);
    }
  };
  for (const r of roots) await walk(r);

  const oneFolder = roots.length === 1 && roots[0].isDirectory;
  return keep(found.map(({ path, file }) => entryFor(oneFolder ? path.split('/').slice(1).join('/') : path, file)));
}

/** Wire a drop zone and its pick buttons to `onFiles(entries)`. */
function dropZone(name, onFiles) {
  const zone = document.querySelector(`[data-drop="${name}"]`);
  zone.addEventListener('dragover', (e) => { e.preventDefault(); zone.classList.add('over'); });
  zone.addEventListener('dragleave', (e) => { if (!zone.contains(e.relatedTarget)) zone.classList.remove('over'); });
  zone.addEventListener('drop', async (e) => {
    e.preventDefault();
    zone.classList.remove('over');
    onFiles(await fromDrop(e.dataTransfer));
  });
  for (const btn of zone.querySelectorAll('[data-pick]')) {
    const input = $(btn.dataset.pick);
    btn.addEventListener('click', () => input.click());
    input.addEventListener('change', () => {
      if (input.files.length) onFiles(fromInput(input));
      input.value = '';
    });
  }
  return zone;
}

// A drop that misses a zone would otherwise navigate away from the page.
window.addEventListener('dragover', (e) => e.preventDefault());
window.addEventListener('drop', (e) => e.preventDefault());

/* ---------- tabs ---------- */

const tabs = ['seal', 'verify', 'one'];
function showTab(name, focus = false) {
  for (const t of tabs) {
    const tab = $(`tab-${t}`);
    tab.setAttribute('aria-selected', String(t === name));
    tab.tabIndex = t === name ? 0 : -1;
    $(`pane-${t}`).hidden = t !== name;
  }
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

/* ---------- tree drawing ---------- */

const TREE_LIMIT = 256;
const COL = 84, ROW = 52, NODE_W = 76, NODE_H = 22, PAD = 12;

/**
 * Draw the tree as SVG, root on top. `marks` maps "level:index" to a class name
 * (on, sibling, dirty, gone). Leaves are focusable and call onPick(index).
 */
function drawTree(levels, { names, marks = new Map(), onPick }) {
  const n = levels[0].length;
  const depth = levels.length;
  const width = Math.max(n * COL, NODE_W) + PAD * 2;
  const height = (depth - 1) * ROW + NODE_H + 30 + PAD * 2;

  // x of every node: leaves evenly spaced, parents centred over their children,
  // promoted nodes directly above the child they were promoted from.
  const xs = [levels[0].map((_, i) => PAD + i * COL + COL / 2)];
  for (let l = 1; l < depth; l++) {
    xs.push(levels[l].map((_, j) => {
      const a = xs[l - 1][2 * j], b = xs[l - 1][2 * j + 1];
      return b === undefined ? a : (a + b) / 2;
    }));
  }
  const y = (l) => PAD + (depth - 1 - l) * ROW;

  const edges = [], nodes = [];
  for (let l = 0; l < depth; l++) {
    for (let j = 0; j < levels[l].length; j++) {
      const mark = marks.get(`${l}:${j}`) ?? '';
      if (l > 0) {
        const kids = [2 * j, 2 * j + 1].filter(k => k < levels[l - 1].length);
        for (const k of kids) {
          const kidMark = marks.get(`${l - 1}:${k}`) ?? '';
          const lit = (m) => m === 'gone' ? 'dirty' : m === 'on' || m === 'dirty' ? m : '';
          const cls = lit(mark) && lit(kidMark) ? lit(kidMark) : '';
          edges.push(s('path', {
            class: `edge ${kids.length === 1 ? 'promoted' : ''} ${cls}`,
            d: `M${xs[l][j]} ${y(l) + NODE_H} L${xs[l - 1][k]} ${y(l - 1)}`,
          }));
        }
      }
      const isRoot = l === depth - 1;
      const isLeaf = l === 0;
      const hex = toHex(levels[l][j]);
      const g = s('g', {
        class: `node ${isRoot ? 'root' : ''} ${isLeaf ? 'leaf' : ''} ${mark}`,
        transform: `translate(${xs[l][j] - NODE_W / 2} ${y(l)})`,
        ...(isLeaf && onPick ? { tabindex: 0, role: 'button', 'aria-label': `Show the proof for ${names[j]}` } : {}),
      },
        s('title', null, isLeaf ? `${names[j]}\nleaf ${hex}` : `${isRoot ? 'root' : 'node'} ${hex}`),
        s('rect', { width: NODE_W, height: NODE_H, rx: 4 }),
        s('text', { x: NODE_W / 2, y: 15, 'text-anchor': 'middle' }, hex.slice(0, 8)));
      if (isLeaf && onPick) {
        g.addEventListener('click', () => onPick(j));
        g.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onPick(j); } });
      }
      nodes.push(g);
      if (isLeaf) {
        const label = basename(names[j]);
        nodes.push(s('text', {
          class: `label ${mark}`, x: xs[0][j], y: y(0) + NODE_H + 16, 'text-anchor': 'middle',
        }, label.length > 11 ? label.slice(0, 10) + '…' : label));
      }
    }
  }

  return s('svg', {
    // Small trees shrink to fit the card; bigger ones keep legible labels and scroll.
    class: `tree-svg ${n <= 16 ? 'fit' : ''}`, width, height, viewBox: `0 0 ${width} ${height}`,
    role: 'img', 'aria-label': `Merkle tree with ${plural(n, 'leaf', 'leaves')} and ${depth} levels`,
  }, edges, nodes);
}

/** Marks for one leaf's path to the root, and the siblings its proof uses. */
function proofMarks(levels, index) {
  const marks = new Map();
  const path = pathIndices(levels, index);
  for (let l = 0; l < levels.length; l++) {
    marks.set(`${l}:${path[l]}`, 'on');
    const sib = path[l] ^ 1;
    if (l < levels.length - 1 && sib < levels[l].length) marks.set(`${l}:${sib}`, 'sibling');
  }
  return marks;
}

function treeCard(levels, names, marks, onPick, extraLegend = []) {
  if (levels[0].length > TREE_LIMIT) {
    return h('div', { class: 'card tree-card' }, h('h2', null, 'Tree'),
      h('p', { class: 'sub' }, `The drawing is skipped above ${TREE_LIMIT} files. Every proof is still listed below.`));
  }
  return h('div', { class: 'card tree-card' },
    h('h2', null, 'Tree'),
    h('p', { class: 'sub' }, 'Root on top, one leaf per file. Pick a leaf or a row to see its proof.'),
    h('div', { class: 'tree-scroll' }, drawTree(levels, { names, marks, onPick })),
    h('div', { class: 'legend' },
      h('span', null, h('i', { class: 'on' }), 'path to the root'),
      h('span', null, h('i', { class: 'sib' }), 'sibling in the proof'),
      extraLegend));
}

/**
 * The proof, step by step: the leaf, each sibling it is combined with, and the root
 * that comes out, compared with the expected root.
 */
async function proofCard({ title, path, contentHash, proof, root, note }) {
  const leaf = await leafHash(path, contentHash);
  const trail = (await foldProof(leaf, proof)).map(toHex);
  const got = trail[trail.length - 1];
  const ok = got === root;

  return h('div', { class: 'card' },
    h('h2', null, title),
    h('p', { class: 'sub' }, `${path} · ${plural(proof.length, 'sibling hash', 'sibling hashes')} to reach the root`),
    note && h('p', { class: 'sub' }, note),
    h('ol', { class: 'steps' },
      h('li', null, h('span', { class: 'op' }, 'content = SHA-256(file)'), h('span', { class: 'val' }, contentHash)),
      h('li', null, h('span', { class: 'op' }, 'leaf = H(0x00 ‖ len ‖ path ‖ content)'), h('span', { class: 'val' }, trail[0])),
      proof.map((step, i) => h('li', null,
        h('span', { class: 'op' }, step.side === 'left'
          ? `step ${i + 1}: H(0x01 ‖ sibling ‖ acc), sibling ${short(step.hash)}`
          : `step ${i + 1}: H(0x01 ‖ acc ‖ sibling), sibling ${short(step.hash)}`),
        h('span', { class: 'val' }, trail[i + 1]))),
      h('li', null,
        h('span', { class: 'op' }, ok ? 'matches the sealed root' : 'does not match the sealed root'),
        h('span', { class: `val ${ok ? 'ok' : 'bad'}` }, ok ? `✓ ${root}` : `✗ expected ${root}`))));
}

function status(name, text) { $(`${name}-status`).textContent = text; }
const progress = (name, verb) => (done, total) => status(name, `${verb} ${done} of ${total}…`);

/* ---------- 1. seal ---------- */

const sealOut = $('seal-out');

dropZone('seal', (entries) => runSeal(entries));
$('demo').addEventListener('click', () => runSeal(demoFiles(), { demo: true }));

async function runSeal(entries, { demo = false } = {}) {
  sealOut.replaceChildren();
  if (!entries.length) { status('seal', 'No files found in that drop.'); return; }
  try {
    const { manifest, levels } = await createSeal(entries, { onProgress: progress('seal', 'Hashing') });
    status('seal', '');
    renderSeal(manifest, levels, demo);
  } catch (err) {
    status('seal', '');
    sealOut.replaceChildren(errorCard(err));
  }
}

function renderSeal(manifest, levels, demo) {
  const total = manifest.files.reduce((sum, f) => sum + f.size, 0);
  const names = manifest.files.map(f => f.path);

  const copyBtn = h('button', { class: 'btn', onclick: () => copy(copyBtn, manifest.root) }, 'copy root');
  const head = h('div', { class: 'card' },
    h('h2', null, 'Sealed'),
    h('p', { class: 'sub' }, `${plural(manifest.files.length, 'file')}, ${bytes(total)}, ${levels.length} tree levels`),
    h('div', { class: 'root-hash' }, manifest.root),
    h('div', { class: 'actions' },
      h('button', { class: 'btn solid', onclick: () => download('seal.json', manifest) }, 'download seal.json'),
      copyBtn,
      h('button', { class: 'btn', onclick: () => { loadVerifySeal(manifest, 'this seal'); showTab('verify'); } }, 'verify against this seal')));

  const hint = demo && h('div', { class: 'card hint' },
    h('h2', null, 'Now tamper with it'),
    h('p', null, 'The demo files are sealed. Edit one of them and verify the set against this seal:'),
    h('div', { class: 'actions' },
      h('button', { class: 'btn solid', onclick: () => runDemoVerify(manifest) }, 'change data/report.csv and verify')));

  const split = h('div', { class: 'split' });
  const rows = new Map();
  const select = async (i) => {
    for (const [j, tr] of rows) tr.classList.toggle('selected', j === i);
    const f = manifest.files[i];
    split.replaceChildren(
      treeCard(levels, names, proofMarks(levels, i), select),
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
  select(0);
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

function setSlot(name, text, tone = '') {
  const el = $(`${name}-state`);
  el.textContent = text;
  el.className = `slot-state ${tone}`;
  el.closest('.drop').classList.toggle('filled', tone === 'ok');
}

function loadVerifySeal(manifest, label) {
  verifyState.manifest = manifest;
  setSlot('verify-seal', `${label}: ${plural(manifest.files.length, 'file')}, root ${short(manifest.root)}`, 'ok');
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
    const result = await verifySet(manifest, entries, { onProgress: progress('verify', 'Hashing') });
    if (run !== verifyRun) return;
    status('verify', '');
    await renderVerify(result);
  } catch (err) {
    if (run !== verifyRun) return;
    status('verify', '');
    verifyOut.replaceChildren(errorCard(err));
  }
}

const ORDER = { modified: 0, missing: 1, renamed: 2, added: 3, unchanged: 4 };
const LABEL = { unchanged: 'unchanged', modified: 'modified', missing: 'missing', added: 'not in seal', renamed: 'renamed' };

async function renderVerify(v) {
  const { manifest, levels, results, intact } = v;
  const bad = results.filter(r => r.status !== 'unchanged');

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
      manifest.createdAt && [h('dt', null, 'sealed at'), h('dd', null, `${manifest.createdAt} (local clock of the sealer)`)]));

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
  const select = async (i) => {
    for (const [j, tr] of rows) tr.classList.toggle('selected', j === i);
    const r = byIndex.get(i);
    const f = manifest.files[i];
    // Damage outranks selection, so a changed path stays red while it is selected.
    const marks = new Map([...proofMarks(levels, i), ...dirty]);
    const present = r.status === 'unchanged' || r.status === 'modified';
    split.replaceChildren(
      treeCard(levels, names, marks, select, [h('span', null, h('i', { class: 'dirty' }), 'changed, missing or renamed')]),
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
  if (first) await select(first.index);
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
    if (run !== oneRun) return;
    status('one', '');
    const fromProof = root === entry.root;
    oneOut.replaceChildren(
      h('div', { class: `card verdict ${result.ok ? 'ok' : 'bad'}` },
        h('h2', null, result.ok ? 'Verified' : 'Does not verify'),
        h('p', null, result.ok
          ? `${file.path} is the file sealed as ${entry.path}, under this root. Checked with ${plural(entry.proof.length, 'sibling hash', 'sibling hashes')} and nothing else from the set.`
          : result.contentHash !== entry.contentHash
            ? `${file.path} is not the file sealed as ${entry.path}: its content hash differs from the sealed one.`
            : `The file matches the sealed content hash, but its proof does not lead to this root.`),
        !fromProof && h('p', { class: 'sub' }, 'Checked against the root you entered, not the one stored in the proof.')),
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
    const bytes = enc.encode(text);
    return { path, size: bytes.length, read: async () => bytes };
  });
}

function runDemoVerify(manifest) {
  verifyState.entries = demoFiles({ 'data/report.csv': DEMO['data/report.csv'].replace('135500', '153500') });
  setSlot('verify-files', 'demo files, with one revenue figure in data/report.csv changed', 'ok');
  loadVerifySeal(manifest, 'demo seal');
  showTab('verify');
}
