/*
 * Signing a seal with ECDSA P-256 over SHA-256, using Web Crypto.
 *
 * The root already commits to every file, so the signature only has to cover the
 * root and the sealing time. The public key travels inside the seal; what makes a
 * signature meaningful is its fingerprint, the SHA-256 of the raw public key, which
 * a verifier compares with one they already know belongs to the sealer.
 */

import { sha256, toHex, fromHex, isHash } from './merkle.js';

export const SIGNATURE_ALG = 'ECDSA-P256-SHA256';
const KEY = { name: 'ECDSA', namedCurve: 'P-256' };
const SIGN = { name: 'ECDSA', hash: 'SHA-256' };
const utf8 = new TextEncoder();

/** The exact bytes that are signed. Fixed text, so other tools can reproduce it. */
export function signedMessage(root, createdAt) {
  return utf8.encode(`merkle-seal v2\nroot ${root}\ncreated ${createdAt ?? ''}\n`);
}

const publicPart = ({ kty, crv, x, y }) => ({ kty, crv, x, y });

const isPublicJwk = (k) => !!k && k.kty === 'EC' && k.crv === 'P-256' &&
  typeof k.x === 'string' && typeof k.y === 'string';

/** True if `sig` has the shape of a seal signature. Whether it is valid is checkSignature's job. */
export function isSignature(sig) {
  return !!sig && sig.alg === SIGNATURE_ALG && isPublicJwk(sig.publicKey) &&
    isHash(sig.fingerprint) && typeof sig.value === 'string' && /^[0-9a-f]{128}$/i.test(sig.value);
}

/** A new signing key pair. Extractable, so the private key can be saved and reused. */
export async function generateSigningKey() {
  const { privateKey, publicKey } = await crypto.subtle.generateKey(KEY, true, ['sign', 'verify']);
  return { privateKey, publicJwk: publicPart(await crypto.subtle.exportKey('jwk', publicKey)) };
}

/** The private key as a JWK, for the sealer to keep. It includes the public half. */
export async function exportSigningKey({ privateKey }) {
  const jwk = await crypto.subtle.exportKey('jwk', privateKey);
  return { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, d: jwk.d };
}

/** Load a private key saved by exportSigningKey. */
export async function importSigningKey(jwk) {
  if (!isPublicJwk(jwk) || typeof jwk.d !== 'string') {
    throw new TypeError('That is not a P-256 private key in JWK form.');
  }
  const privateKey = await crypto.subtle.importKey('jwk', { ...publicPart(jwk), d: jwk.d }, KEY, true, ['sign']);
  return { privateKey, publicJwk: publicPart(jwk) };
}

/** SHA-256 of the uncompressed public point (0x04 ‖ x ‖ y), as hex. */
export async function fingerprint(publicJwk) {
  const key = await crypto.subtle.importKey('jwk', publicPart(publicJwk), KEY, true, ['verify']);
  return toHex(await sha256(new Uint8Array(await crypto.subtle.exportKey('raw', key))));
}

/** "3f2a 9c1b 77d0 41e8" style short form of a fingerprint, for people to compare. */
export const shortFingerprint = (fp) => fp.slice(0, 16).match(/.{4}/g).join(' ');

/** Sign a seal's root and time. Returns the signature object stored in the seal. */
export async function signRoot({ root, createdAt }, { privateKey, publicJwk }) {
  const value = await crypto.subtle.sign(SIGN, privateKey, signedMessage(root, createdAt));
  return {
    alg: SIGNATURE_ALG,
    publicKey: publicPart(publicJwk),
    fingerprint: await fingerprint(publicJwk),
    value: toHex(new Uint8Array(value)),
  };
}

/**
 * Check the signature on anything with { root, createdAt, signature }.
 * Returns { present, valid, fingerprint }. The fingerprint is recomputed from the
 * key rather than read from the seal, so a mislabelled key cannot pass.
 */
export async function checkSignature({ root, createdAt, signature }) {
  if (!signature) return { present: false, valid: false, fingerprint: null };
  if (!isSignature(signature)) return { present: true, valid: false, fingerprint: null };
  try {
    const fp = await fingerprint(signature.publicKey);
    const key = await crypto.subtle.importKey('jwk', publicPart(signature.publicKey), KEY, false, ['verify']);
    const ok = await crypto.subtle.verify(SIGN, key, fromHex(signature.value), signedMessage(root, createdAt));
    return { present: true, valid: ok && fp === signature.fingerprint.toLowerCase(), fingerprint: fp };
  } catch {
    // A key that is not a point on the curve cannot be imported.
    return { present: true, valid: false, fingerprint: null };
  }
}
