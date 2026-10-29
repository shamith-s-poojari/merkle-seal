// Turning drops and file pickers into { path, size, file, read() } entries.

import { $, basename } from './dom.js';

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
export function dropZone(name, onFiles) {
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
