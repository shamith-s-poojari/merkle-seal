// Drawing Merkle trees as SVG, and showing an inclusion proof step by step.

import { toHex, leafHash, foldProof, pathIndices } from '../merkle.js';
import { h, s, short, plural, basename } from './dom.js';

export const TREE_LIMIT = 256;
const COL = 84, ROW = 52, NODE_W = 76, NODE_H = 22, PAD = 12;
const reducedMotion = matchMedia('(prefers-reduced-motion: reduce)');

/**
 * Draw a tree, root on top. `marks` maps "level:index" to a class name (on, sibling,
 * dirty, gone). Leaves are focusable and call onPick(index) when given. With
 * `animate`, the tree builds up from the leaves one level at a time.
 */
export function drawTree(levels, { names, marks = new Map(), onPick, animate = false }) {
  const n = levels[0].length;
  const depth = levels.length;
  const width = Math.max(n * COL, NODE_W) + PAD * 2;
  const height = (depth - 1) * ROW + NODE_H + 30 + PAD * 2;
  const grow = animate && !reducedMotion.matches;
  const delay = (el, level) => { if (grow) el.style.setProperty('--d', `${level * 140}ms`); return el; };

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
  const lit = (m) => m === 'gone' ? 'dirty' : m === 'on' || m === 'dirty' ? m : '';

  const edges = [], nodes = [];
  for (let l = 0; l < depth; l++) {
    for (let j = 0; j < levels[l].length; j++) {
      const mark = marks.get(`${l}:${j}`) ?? '';
      if (l > 0) {
        const kids = [2 * j, 2 * j + 1].filter(k => k < levels[l - 1].length);
        for (const k of kids) {
          const kidMark = lit(marks.get(`${l - 1}:${k}`) ?? '');
          edges.push(delay(s('path', {
            class: `edge ${kids.length === 1 ? 'promoted' : ''} ${lit(mark) && kidMark ? kidMark : ''}`,
            d: `M${xs[l][j]} ${y(l) + NODE_H} L${xs[l - 1][k]} ${y(l - 1)}`,
          }), l));
        }
      }
      const isRoot = l === depth - 1;
      const isLeaf = l === 0;
      const hex = toHex(levels[l][j]);
      const g = delay(s('g', {
        class: `node ${isRoot ? 'root' : ''} ${isLeaf ? 'leaf' : ''} ${isLeaf && onPick ? 'pickable' : ''} ${mark}`,
        transform: `translate(${xs[l][j] - NODE_W / 2} ${y(l)})`,
        ...(isLeaf && onPick ? { tabindex: 0, role: 'button', 'aria-label': `Show the proof for ${names[j]}` } : {}),
      },
        s('title', null, isLeaf ? `${names[j]}\nleaf ${hex}` : `${isRoot ? 'root' : 'node'} ${hex}`),
        s('rect', { width: NODE_W, height: NODE_H, rx: 4 }),
        s('text', { x: NODE_W / 2, y: 15, 'text-anchor': 'middle' }, hex.slice(0, 8))), l);
      if (isLeaf && onPick) {
        g.addEventListener('click', () => onPick(j));
        g.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onPick(j); } });
      }
      nodes.push(g);
      if (isLeaf) {
        const label = basename(names[j]);
        nodes.push(delay(s('text', {
          class: `label ${mark}`, x: xs[0][j], y: y(0) + NODE_H + 16, 'text-anchor': 'middle',
        }, label.length > 11 ? label.slice(0, 10) + '…' : label), 0));
      }
    }
  }

  return s('svg', {
    // Small trees shrink to fit the card; bigger ones keep legible labels and scroll.
    class: `tree-svg ${n <= 16 ? 'fit' : ''} ${grow ? 'grow' : ''}`, width, height, viewBox: `0 0 ${width} ${height}`,
    role: 'img', 'aria-label': `Merkle tree with ${plural(n, 'leaf', 'leaves')} and ${depth} levels`,
  }, edges, nodes);
}

/** Marks for one leaf's path to the root, and the siblings its proof uses. */
export function proofMarks(levels, index) {
  const marks = new Map();
  const path = pathIndices(levels, index);
  for (let l = 0; l < levels.length; l++) {
    marks.set(`${l}:${path[l]}`, 'on');
    const sib = path[l] ^ 1;
    if (l < levels.length - 1 && sib < levels[l].length) marks.set(`${l}:${sib}`, 'sibling');
  }
  return marks;
}

export function treeCard(levels, names, { marks, onPick, animate, legend = [] }) {
  if (levels[0].length > TREE_LIMIT) {
    return h('div', { class: 'card tree-card' }, h('h2', null, 'Tree'),
      h('p', { class: 'sub' }, `The drawing is skipped above ${TREE_LIMIT} files. Every proof is still listed below.`));
  }
  return h('div', { class: 'card tree-card' },
    h('h2', null, 'Tree'),
    h('p', { class: 'sub' }, 'Root on top, one leaf per file. Pick a leaf or a row to see its proof.'),
    h('div', { class: 'tree-scroll' }, drawTree(levels, { names, marks, onPick, animate })),
    h('div', { class: 'legend' },
      h('span', null, h('i', { class: 'on' }), 'path to the root'),
      h('span', null, h('i', { class: 'sib' }), 'sibling in the proof'),
      legend));
}

/**
 * The proof, step by step: the leaf, each sibling it is combined with, and the root
 * that comes out, compared with the expected root.
 */
export async function proofCard({ title, path, contentHash, proof, root, note }) {
  const leaf = await leafHash(path, contentHash);
  const trail = (await foldProof(leaf, proof)).map(toHex);
  const ok = trail[trail.length - 1] === root;

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
