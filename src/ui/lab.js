// The attack lab: each attack runs live against a weakened tree and the real one.

import { toHex } from '../merkle.js';
import { secondPreimageAttack, duplicateOddAttack } from '../attacks.js';
import { h } from './dom.js';
import { drawTree } from './tree.js';

const ATTACKS = [
  {
    id: 'preimage',
    title: 'Second preimage: two hashes posing as files',
    what: 'The attacker leaves the four sealed files alone. They hand over a different set of two "files", each one just two real leaf hashes glued together (64 bytes). If leaves and internal nodes are hashed the same way, each fake file hashes to a real internal node, so the fake set rebuilds the genuine root.',
    defence: 'domain separation',
    weak: 'leaf = H(file), node = H(l ‖ r)',
    strong: 'leaf = H(0x00 ‖ …), node = H(0x01 ‖ l ‖ r)',
    run: (on) => secondPreimageAttack({ domainSeparation: on }),
    fakeLabel: 'fake set, 2 files',
    // The fake leaves are meant to equal the genuine level-1 nodes.
    highlight: (r) => r.collides ? [['genuine', '1:0'], ['genuine', '1:1'], ['fake', '0:0'], ['fake', '0:1']] : [],
    detail: (r) => h('dl', { class: 'kv' }, r.forged.map(f => [
      h('dt', null, f.path), h('dd', { class: 'hash' }, f.hex),
    ])),
  },
  {
    id: 'cve',
    title: 'CVE-2012-2459: the duplicated odd node',
    what: 'With three files the last one has no partner. Bitcoin paired it with a copy of itself, which builds exactly the same tree as a four-file list that names the third file twice. Two different sets, one root, so the root no longer says what was sealed.',
    defence: 'promoting odd nodes',
    weak: 'odd node paired with itself',
    strong: 'odd node moved up unchanged',
    run: (on) => duplicateOddAttack({ promote: on }),
    fakeLabel: 'fake set, 3rd file listed twice',
    highlight: (r) => r.collides ? [['genuine', '0:2'], ['fake', '0:2'], ['fake', '0:3']] : [],
    detail: () => null,
  },
];

function attackCard(attack) {
  const body = h('div');
  const buttons = {};
  let run = 0;

  async function show(on) {
    const mine = ++run;
    for (const [k, b] of Object.entries(buttons)) b.setAttribute('aria-pressed', String((k === 'on') === on));
    const r = await attack.run(on);
    if (mine !== run) return;

    const marks = { genuine: new Map(), fake: new Map() };
    for (const [which, key] of attack.highlight(r)) marks[which].set(key, 'on');
    for (const t of ['genuine', 'fake']) marks[t].set(`${r[t].levels.length - 1}:0`, r.collides ? 'dirty' : '');

    const tree = (t, label) => h('figure', { class: 'lab-tree' },
      h('figcaption', null, label),
      drawTree(r[t].levels, { names: r[t].names, marks: marks[t], animate: true }),
      h('p', { class: `lab-root ${r.collides ? 'mismatch' : ''}` }, `root ${toHex(r[t].root).slice(0, 16)}…`));

    body.replaceChildren(
      h('div', { class: `lab-verdict ${r.collides ? 'bad' : 'ok'}` },
        r.collides
          ? `Forged. A different set of files produces the same root, so a seal could not tell them apart.`
          : `Blocked. The fake set produces a different root, so the forgery is caught.`),
      h('div', { class: 'lab-trees' },
        tree('genuine', `genuine set, ${r.genuine.names.length} files`),
        tree('fake', attack.fakeLabel)),
      attack.detail(r));
  }

  buttons.off = h('button', { class: 'seg', onclick: () => show(false) }, h('b', null, 'weakened'), h('span', null, attack.weak));
  buttons.on = h('button', { class: 'seg', onclick: () => show(true) }, h('b', null, 'Merkle Seal'), h('span', null, attack.strong));

  const card = h('section', { class: 'card lab-card', 'aria-labelledby': `lab-${attack.id}` },
    h('h2', { id: `lab-${attack.id}` }, attack.title),
    h('p', { class: 'lab-what' }, attack.what),
    h('div', { class: 'segs', role: 'group', 'aria-label': `Toggle ${attack.defence}` }, buttons.off, buttons.on),
    body);
  show(false);
  return card;
}

export function renderLab(container) {
  container.replaceChildren(...ATTACKS.map(attackCard));
}
