//
// CSP1 suite operations: ECDSA P-256/SHA-256 message signatures (raw 64-byte
// r‖s) and HPKE body sealing with the §5.1 AAD binding.
//

import { p256 } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha2';
import { concatBytes, utf8Bytes } from './encoding.js';
import * as hpke from './hpke.js';

export const PROTOCOL_LABEL = 'CSP1';
const HPKE_INFO = utf8Bytes('CSP1 body');

export interface KeyPair {
  privateKey: Uint8Array;
  /// SEC1 compressed, 33 bytes.
  publicKey: Uint8Array;
}

export function generateKeyPair(): KeyPair {
  const privateKey = p256.utils.randomPrivateKey();
  return { privateKey, publicKey: p256.getPublicKey(privateKey, true) };
}

export function publicKeyFor(privateKey: Uint8Array): Uint8Array {
  return p256.getPublicKey(privateKey, true);
}

/// `"CSP1|" + type + "|" + destinationHost + "|" + canonicalEnvelope` (§6).
export function signingInput(
  type: string,
  destinationHost: string,
  canonicalEnvelope: string,
): Uint8Array {
  return utf8Bytes(`${PROTOCOL_LABEL}|${type}|${destinationHost}|${canonicalEnvelope}`);
}

export function sign(input: Uint8Array, privateKey: Uint8Array): Uint8Array {
  return p256.sign(sha256(input), privateKey).toCompactRawBytes();
}

export function verify(
  signature: Uint8Array,
  input: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  if (signature.length !== 64) return false;
  try {
    // lowS: false — CryptoKit does not normalize S.
    return p256.verify(signature, sha256(input), publicKey, { lowS: false });
  } catch {
    return false;
  }
}

function bodyAAD(type: string, pairingId: string, ctr: number): Uint8Array {
  return utf8Bytes(`${PROTOCOL_LABEL}|${type}|${pairingId}|${ctr}`);
}

/// HPKE seal returning `enc ‖ ct` (§5.1).
export function sealBody(
  plaintext: Uint8Array,
  recipientKemPublicKey: Uint8Array,
  type: string,
  pairingId: string,
  ctr: number,
  testOnlyEphemeralPrivateKey?: Uint8Array,
): Uint8Array {
  const options: { ephemeralPrivateKey?: Uint8Array } = {};
  if (testOnlyEphemeralPrivateKey) options.ephemeralPrivateKey = testOnlyEphemeralPrivateKey;
  const { encapsulatedKey, ciphertext } = hpke.seal(
    recipientKemPublicKey,
    HPKE_INFO,
    bodyAAD(type, pairingId, ctr),
    plaintext,
    options,
  );
  return concatBytes(encapsulatedKey, ciphertext);
}

/// HPKE open of `enc ‖ ct` (§5.1).
export function openBody(
  sealed: Uint8Array,
  kemPrivateKey: Uint8Array,
  type: string,
  pairingId: string,
  ctr: number,
): Uint8Array {
  if (sealed.length <= hpke.ENCAPSULATED_KEY_LENGTH) {
    throw new Error('CSP1: sealed body too short');
  }
  return hpke.open(
    kemPrivateKey,
    HPKE_INFO,
    bodyAAD(type, pairingId, ctr),
    sealed.subarray(0, hpke.ENCAPSULATED_KEY_LENGTH),
    sealed.subarray(hpke.ENCAPSULATED_KEY_LENGTH),
  );
}

export function sha256Bytes(input: Uint8Array): Uint8Array {
  return sha256(input);
}

/// Rotation possession-proof input (§11).
export function rotationProofInput(
  pairingId: string,
  ctr: number,
  newSigPub: Uint8Array | undefined,
  newKemPub: Uint8Array | undefined,
  toBase64Url: (bytes: Uint8Array) => string,
): Uint8Array {
  const fields = [
    `${PROTOCOL_LABEL} rotate`,
    pairingId,
    String(ctr),
    newSigPub ? toBase64Url(newSigPub) : '',
    newKemPub ? toBase64Url(newKemPub) : '',
  ];
  return utf8Bytes(fields.join('|'));
}
