/*
 * The dashboard: KPI cards, the tree, the status donut and the files table for the
 * current seal, plus the latest verification against it when there is one.
 */

import { pathIndices } from '../merkle.js';
import { describeCounts, proofDocument } from '../seal.js';
import { shortFingerprint } from '../sign.js';
import { $, h, short, plural, bytes, duration, download, copy, basename } from './dom.js';
import { icon } from './icons.js';
import { donut } from './charts.js';
import { drawTree, proofMarks, proofCard, TREE_LIMIT } from './tree.js';

const LABEL = {
  sealed: 'sealed', unchanged: 'unchanged', modified: 'modified',
  missing: 'missing', added: 'not in seal', renamed: 'renamed',
};
const ORDER = { modified: 0, missing: 1, renamed: 2, added: 3, unchanged: 4, sealed: 5 };

// Filters survive re-renders, so a new verification keeps the user's search.
const filters = { text: '', status: 'all' };
let current = null;   // { model, rows, select(i), table }

/**
 * view: { manifest, levels, ms, demo, engine, signature, verification: { result, ms } | null }
 * actions: { newSeal, verifyFiles, tamperDemo, clearVerification, openView(name) }
 */
export function renderDashboard(host, view, actions) {
  const { manifest, levels, verification } = view;
  const v = verification?.result ?? null;
  const rows = v
    ? [...v.results].sort((a, b) => ORDER[a.status] - ORDER[b.status]).map(r => ({
      index: r.index, path: r.path, from: r.from, status: r.status,
      size: r.size ?? r.sealed.size, sealedHash: r.sealed?.contentHash ?? null, nowHash: r.contentHash ?? null,
    }))
    : manifest.files.map((f, i) => ({
      index: i, path: f.path, status: 'sealed', size: f.size, sealedHash: f.contentHash, nowHash: null,
    }));

  // Changed leaves, and every node above them, turn red on the tree.
  const dirty = new Map();
  for (const r of v?.results ?? []) {
    if (r.index === null || r.status === 'unchanged') continue;
    for (const [l, j] of pathIndices(levels, r.index).entries()) dirty.set(`${l}:${j}`, 'dirty');
    if (r.status !== 'modified') dirty.set(`0:${r.index}`, 'gone');
  }

  const treeHost = h('div', { class: 'tree-host' });
  const pathSelect = h('select', { class: 'select', 'aria-label': 'Show the proof path for' },
    manifest.files.map((f, i) => h('option', { value: i }, f.path)));
  const tbody = h('tbody');
  const model = { view, rows, dirty, treeHost, pathSelect, tbody, actions, selected: 0 };

  const select = (i, animate = false) => {
    model.selected = i;
    pathSelect.value = String(i);
    const names = manifest.files.map(f => f.path);
    treeHost.replaceChildren(levels[0].length > TREE_LIMIT
      ? h('p', { class: 'muted' }, `The drawing is skipped above ${TREE_LIMIT} files. Every proof is still in the table.`)
      : drawTree(levels, {
        names, animate, onPick: (j) => select(j),
        marks: new Map([...proofMarks(levels, i), ...dirty]),
      }));
    for (const tr of tbody.children) tr.classList.toggle('selected', Number(tr.dataset.index) === i && tr.dataset.index !== '');
  };
  pathSelect.addEventListener('change', () => select(Number(pathSelect.value)));

  current = { model, select };
  host.replaceChildren(
    banner(view, actions),
    kpis(view, actions),
    h('div', { class: 'dash-row' }, treePanel(view, model), distributionPanel(view)),
    filesPanel(view, model));
  fillTable();

  const firstBad = rows.find(r => r.index !== null && r.status !== 'unchanged' && r.status !== 'sealed');
  select(firstBad ? firstBad.index : 0, true);
}

/** Re-filter the table after the search box changes, without redrawing anything else. */
export function setSearch(text) {
  filters.text = text.trim().toLowerCase();
  if (current) fillTable();
}

/* ---------- pieces ---------- */

const listNames = (names, max = 4) =>
  names.length <= max ? names.join(', ') : `${names.slice(0, max).join(', ')} and ${names.length - max} more`;

function banner({ demo, verification, manifest }, actions) {
  const v = verification?.result;
  if (!v) {
    if (!demo) return '';
    return h('div', { class: 'banner info' },
      h('span', { class: 'banner-icon' }, icon('bolt')),
      h('div', { class: 'banner-text' },
        h('b', null, 'Demo set sealed in this tab.'),
        h('span', null, ' Change one number in one file and verify, or try to forge a root in the attack lab.')),
      h('div', { class: 'banner-actions' },
        h('button', { class: 'btn btn-solid', onclick: actions.tamperDemo }, 'Tamper and verify'),
        h('button', { class: 'btn', onclick: () => actions.openView('lab') }, 'Attack lab')));
  }
  const bad = v.results.filter(r => r.status !== 'unchanged');
  return h('div', { class: `banner ${v.intact ? 'ok' : 'bad'}`, role: 'status' },
    h('span', { class: 'banner-icon' }, icon(v.intact ? 'shield' : 'alert')),
    h('div', { class: 'banner-text' },
      h('b', null, v.intact ? 'Intact. ' : 'Changed. '),
      h('span', null, v.intact
        ? `All ${plural(v.results.length, 'file')} match the seal and the rebuilt root equals the sealed root.`
        : `${describeCounts(v.counts)}: ${listNames(bad.map(r => r.status === 'renamed' ? `${r.from} → ${r.path}` : r.path))}.`),
      h('span', { class: 'banner-meta' },
        `Checked ${bytes(v.results.reduce((n, r) => n + (r.contentHash ? r.size : 0), 0))} in ${duration(verification.ms)} · root now `,
        h('code', { class: v.intact ? 'match' : 'mismatch' }, v.currentRoot ? short(v.currentRoot) : 'none'),
        ` · sealed `, h('code', null, short(manifest.root)))),
    h('div', { class: 'banner-actions' },
      h('button', { class: 'btn', onclick: actions.verifyFiles }, 'Verify again'),
      h('button', { class: 'btn', onclick: actions.clearVerification }, 'Clear')));
}

function kpi({ label, iconName, value, pill, tone = '', hl = false, onclick }) {
  return h('article', { class: `kpi ${hl ? 'hl' : ''} ${tone}` },
    h('header', null, h('span', { class: 'kpi-icon' }, icon(iconName)), h('h3', null, label)),
    h('p', { class: 'kpi-value' }, value),
    onclick
      ? h('button', { class: 'kpi-pill link-pill', onclick }, pill)
      : h('p', { class: 'kpi-pill' }, pill));
}

function kpis({ manifest, levels, ms, engine, signature, verification }, actions) {
  const n = manifest.files.length;
  const total = manifest.files.reduce((sum, f) => sum + f.size, 0);
  const proof = manifest.files.reduce((sum, f) => sum + f.proof.length, 0) / n;
  const v = verification?.result;
  const bad = v ? v.results.filter(r => r.status !== 'unchanged').length : 0;

  return h('div', { class: 'kpis' },
    kpi({
      label: 'Files sealed', iconName: 'layers', value: n.toLocaleString('en'),
      pill: `${bytes(total)} hashed in ${duration(ms)} on ${engine}`,
    }),
    kpi({
      label: v ? 'Changed files' : 'Integrity', iconName: v && !v.intact ? 'alert' : 'shield', hl: true,
      tone: v ? (v.intact ? 'ok' : 'bad') : '',
      value: v ? `${bad} / ${v.results.length}` : 'Sealed',
      pill: v ? (v.intact ? 'rebuilt root matches the seal' : 'rebuilt root differs from the seal') : `root ${manifest.root.slice(0, 12)}…`,
    }),
    kpi({
      label: 'Proof per file', iconName: 'tree', value: `${Number(proof.toFixed(1))} hashes`,
      pill: `${levels.length} tree levels · a flat list needs ${n.toLocaleString('en')}`,
    }),
    kpi({
      label: 'Signature', iconName: 'key',
      tone: signature.present ? (signature.valid ? 'ok' : 'bad') : '',
      value: signature.present ? (signature.valid ? 'Signed' : 'Invalid') : 'Unsigned',
      pill: signature.present && signature.fingerprint ? `key ${shortFingerprint(signature.fingerprint)}` : 'set up a signing key →',
      onclick: () => actions.openView('key'),
    }));
}

function treePanel({ manifest }, model) {
  const copyBtn = h('button', { class: 'icon-btn', title: 'Copy root', 'aria-label': 'Copy root', onclick: () => copy(copyBtn, manifest.root) }, icon('copy'));
  return h('section', { class: 'panel tree-panel', 'aria-labelledby': 'tree-h' },
    h('header', { class: 'panel-head' },
      h('div', null,
        h('h2', { id: 'tree-h' }, 'Merkle tree'),
        h('p', { class: 'panel-sub' }, 'root ', h('code', null, short(manifest.root)), copyBtn)),
      h('label', { class: 'select-wrap' }, h('span', null, 'Proof path'), model.pathSelect)),
    h('div', { class: 'tree-stage' }, model.treeHost),
    h('div', { class: 'legend' },
      h('span', null, h('i', { class: 'on' }), 'path to the root'),
      h('span', null, h('i', { class: 'sib' }), 'sibling in the proof'),
      h('span', null, h('i', { class: 'dirty' }), 'changed, missing or renamed'),
      h('span', { class: 'muted' }, 'pick a leaf to follow its proof')));
}

function distributionPanel({ manifest, verification }) {
  const v = verification?.result;
  const n = manifest.files.length;
  const segments = v
    ? ['unchanged', 'modified', 'missing', 'added', 'renamed'].map(k => ({ key: k, label: LABEL[k], value: v.counts[k] }))
    : [{ key: 'sealed', label: 'sealed', value: n }];
  const intactShare = v ? Math.round(100 * v.counts.unchanged / v.results.length) : 100;
  return h('section', { class: 'panel dist-panel', 'aria-labelledby': 'dist-h' },
    h('header', { class: 'panel-head' },
      h('div', null,
        h('h2', { id: 'dist-h' }, 'Integrity distribution'),
        h('p', { class: 'panel-sub' }, v ? 'files by status in the last verification' : 'verify the set to see what changed'))),
    donut(segments, { centre: `${intactShare}%`, caption: v ? 'unchanged' : 'sealed' }));
}

function filesPanel({ manifest, verification }, model) {
  const statuses = [...new Set(model.rows.map(r => r.status))];
  const statusSelect = h('select', { class: 'select', 'aria-label': 'Filter by status' },
    h('option', { value: 'all' }, 'All statuses'),
    statuses.map(s => h('option', { value: s }, LABEL[s])));
  if (!statuses.includes(filters.status)) filters.status = 'all';
  statusSelect.value = filters.status;
  statusSelect.addEventListener('change', () => { filters.status = statusSelect.value; fillTable(); });

  const hasNow = !!verification;
  model.count = h('span', { class: 'count' });
  return h('section', { class: 'panel files-panel', 'aria-labelledby': 'files-h' },
    h('header', { class: 'panel-head' },
      h('div', null, h('h2', { id: 'files-h' }, 'Files ', model.count),
        h('p', { class: 'panel-sub' }, hasNow ? 'as checked against the seal' : 'as sealed')),
      h('div', { class: 'panel-tools' },
        statusSelect,
        h('button', { class: 'btn', onclick: model.actions.verifyFiles }, icon('check'), h('span', null, 'Verify files')),
        h('button', { class: 'btn', onclick: () => download('seal.json', manifest) }, icon('download'),
          h('span', null, manifest.signature ? 'Signed seal' : 'Seal.json')))),
    h('div', { class: 'table-wrap' }, h('table', null,
      h('thead', null, h('tr', null,
        h('th', null, 'Status'), h('th', null, 'Path'), h('th', null, 'Size'),
        h('th', null, 'Sealed SHA-256'), hasNow && h('th', null, 'SHA-256 now'), h('th', { class: 'act' }, 'Action'))),
      model.tbody)));
}

function fillTable() {
  const { model } = current;
  const { rows, tbody, view } = model;
  const hasNow = !!view.verification;
  const shown = rows.filter(r =>
    (filters.status === 'all' || r.status === filters.status) &&
    (!filters.text || r.path.toLowerCase().includes(filters.text) || r.from?.toLowerCase().includes(filters.text)));

  model.count.textContent = shown.length === rows.length ? String(rows.length) : `${shown.length} of ${rows.length}`;
  tbody.replaceChildren(...shown.map(r => {
    const tr = h('tr', { 'data-index': r.index ?? '' },
      h('td', null, h('span', { class: `pill ${r.status}` }, LABEL[r.status])),
      h('td', { class: 'path' }, r.path, r.from && h('span', { class: 'from' }, `was ${r.from}`)),
      h('td', { class: 'num' }, bytes(r.size)),
      h('td', { class: 'h' }, r.sealedHash ? short(r.sealedHash) : '—'),
      hasNow && h('td', { class: `h ${r.status === 'modified' ? 'mismatch' : ''}` }, r.nowHash ? short(r.nowHash) : '—'),
      h('td', { class: 'act' }, r.index === null ? h('span', { class: 'muted' }, 'no proof') : h('button', {
        class: 'btn btn-small', onclick: (e) => { e.stopPropagation(); openProof(r.index); },
      }, icon('eye'), h('span', null, 'View'))));
    if (r.index !== null) tr.addEventListener('click', () => current.select(r.index));
    if (r.index === model.selected) tr.classList.add('selected');
    return tr;
  }));
  if (!shown.length) {
    tbody.append(h('tr', { class: 'empty' }, h('td', { colspan: hasNow ? 6 : 5 }, 'No files match the filter.')));
  }
}

/* ---------- proof drawer ---------- */

let lastFocus = null;

async function openProof(index) {
  const { view } = current.model;
  const { manifest } = view;
  const f = manifest.files[index];
  const r = view.verification?.result.results.find(x => x.index === index);
  const present = r && (r.status === 'unchanged' || r.status === 'modified');
  current.select(index);

  const body = $('drawer-body');
  $('drawer-title').textContent = basename(f.path);
  body.replaceChildren(
    h('dl', { class: 'kv' },
      h('dt', null, 'path'), h('dd', null, f.path),
      h('dt', null, 'status'), h('dd', null, h('span', { class: `pill ${r?.status ?? 'sealed'}` }, LABEL[r?.status ?? 'sealed'])),
      h('dt', null, 'size'), h('dd', null, bytes(f.size)),
      h('dt', null, 'sealed sha-256'), h('dd', { class: 'hash' }, f.contentHash),
      present && [h('dt', null, 'sha-256 now'), h('dd', { class: `hash ${r.status === 'modified' ? 'mismatch' : ''}` }, r.contentHash)]),
    await proofCard({
      title: present ? 'The proof, using the file as it is now' : 'The proof, as sealed',
      path: f.path,
      contentHash: present ? r.contentHash : f.contentHash,
      proof: f.proof,
      root: manifest.root,
      note: r?.status === 'renamed' ? `This file now lives at ${r.path}. A leaf includes its path, so it no longer proves under the old one.`
        : r?.status === 'missing' ? 'This file was not supplied when the set was verified.' : null,
    }),
    h('div', { class: 'actions' },
      h('button', { class: 'btn btn-solid', onclick: () => download(`${basename(f.path)}.proof.json`, proofDocument(manifest, f.path)) },
        icon('download'), h('span', null, 'Download proof.json'))));

  lastFocus = document.activeElement;
  $('drawer').hidden = false;
  document.body.classList.add('locked');
  $('drawer').querySelector('.drawer-panel').focus();
}

function closeProof() {
  if ($('drawer').hidden) return;
  $('drawer').hidden = true;
  document.body.classList.remove('locked');
  lastFocus?.focus?.();
}

for (const el of document.querySelectorAll('#drawer [data-close]')) el.addEventListener('click', closeProof);
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeProof(); });
