// Small DOM helpers shared by the UI modules.

import { SealError } from '../seal.js';

export const $ = (id) => document.getElementById(id);
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

/** h('div', { class: 'card', onclick }, ...children) builds an HTML element. */
export const h = (tag, attrs, ...kids) => build(document.createElement(tag), attrs, kids);
/** The same for SVG elements. */
export const s = (tag, attrs, ...kids) => build(document.createElementNS(SVG, tag), attrs, kids);

export const short = (hex) => hex.slice(0, 10) + '…';
export const plural = (n, one, many = `${one}s`) => `${n.toLocaleString('en')} ${n === 1 ? one : many}`;
export const basename = (path) => path.slice(path.lastIndexOf('/') + 1);

export function bytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1073741824) return `${(n / 1048576).toFixed(1)} MB`;
  return `${(n / 1073741824).toFixed(2)} GB`;
}

export function duration(ms) {
  return ms < 1000 ? `${Math.max(1, Math.round(ms))} ms` : `${(ms / 1000).toFixed(2)} s`;
}

export function download(name, data) {
  const blob = new Blob([JSON.stringify(data, null, 2) + '\n'], { type: 'application/json' });
  const a = h('a', { href: URL.createObjectURL(blob), download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

export async function copy(button, text) {
  const label = button.textContent;
  try { await navigator.clipboard.writeText(text); button.textContent = 'copied'; }
  catch { button.textContent = 'copy failed'; }
  setTimeout(() => { button.textContent = label; }, 1400);
}

/** Ask for one local file and resolve with it, or with null if the picker is closed. */
export function pickFile(accept) {
  return new Promise((resolve) => {
    const input = h('input', { type: 'file', accept, hidden: true });
    input.addEventListener('change', () => { resolve(input.files[0] ?? null); input.remove(); });
    input.addEventListener('cancel', () => { resolve(null); input.remove(); });
    document.body.append(input);
    input.click();
  });
}

export function errorCard(err) {
  const problems = err instanceof SealError ? err.problems : [];
  return h('div', { class: 'card verdict bad', role: 'alert' },
    h('h2', null, err instanceof SealError ? 'Cannot use that' : 'Something went wrong'),
    h('p', null, err.message),
    problems.length > 0 && h('ul', null, problems.map(p => h('li', null, p.path ? `${p.path}: ${p.reason}` : p.reason))));
}

/** One-line status under a pane, e.g. "Hashing 3 of 40…". */
export function status(name, text) { $(`${name}-status`).textContent = text; }

/** Show a message in a drop zone and mark it filled or failed. */
export function setSlot(name, text, tone = '') {
  const el = $(`${name}-state`);
  el.textContent = text;
  el.className = `slot-state ${tone}`;
  el.closest('.drop').classList.toggle('filled', tone === 'ok');
}
