// The sealer's signing key: generate, load, save, and the panel that manages it.
// The key only ever lives in this tab's memory unless the user saves it.

import {
  generateSigningKey, exportSigningKey, importSigningKey, fingerprint, shortFingerprint,
} from '../sign.js';
import { h, download, pickFile } from './dom.js';

let signer = null;
const listeners = new Set();

/** The active { privateKey, publicJwk, fingerprint }, or null when not signing. */
export const currentSigner = () => signer;
export const onSignerChange = (fn) => listeners.add(fn);

async function setSigner(next) {
  signer = next && { ...next, fingerprint: await fingerprint(next.publicJwk) };
  for (const fn of listeners) fn();
}

export function signingPanel() {
  const note = h('p', { class: 'sub', role: 'status' });
  const fail = (err) => { note.textContent = err.message; note.classList.add('mismatch'); };

  const load = async () => {
    const file = await pickFile('.json,application/json');
    if (!file) return;
    try { await setSigner(await importSigningKey(JSON.parse(await file.text()))); }
    catch (err) { fail(err instanceof SyntaxError ? new Error('That key file is not valid JSON.') : err); }
  };

  if (!signer) {
    return h('div', { class: 'sign-panel' },
      h('p', null, h('b', null, 'Unsigned. '),
        'The root proves the files have not changed, not who sealed them. Sign it with an ECDSA P-256 key and the seal carries that proof too.'),
      h('div', { class: 'actions' },
        h('button', { class: 'btn', onclick: () => generateSigningKey().then(setSigner).catch(fail) }, 'generate a signing key'),
        h('button', { class: 'btn', onclick: load }, 'use a saved key')),
      note);
  }

  return h('div', { class: 'sign-panel signed' },
    h('p', null, h('b', null, 'Signed '), 'with key ', h('code', { class: 'fp' }, shortFingerprint(signer.fingerprint)),
      '. Verifiers see this fingerprint and compare it with the one they know is yours.'),
    h('div', { class: 'actions' },
      h('button', {
        class: 'btn', title: 'Keep this file private. Anyone holding it can sign as you.',
        onclick: async () => download(`signing-key-${signer.fingerprint.slice(0, 8)}.private.jwk.json`, await exportSigningKey(signer)),
      }, 'save private key'),
      h('button', { class: 'btn', onclick: load }, 'use a different key'),
      h('button', { class: 'btn', onclick: () => setSigner(null) }, 'stop signing')),
    h('p', { class: 'sub' }, 'The private key lives only in this tab and is gone on reload unless you save it.'),
    note);
}
