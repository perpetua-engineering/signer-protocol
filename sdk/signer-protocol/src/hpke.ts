//
// Minimal HPKE (RFC 9180) for the Cryptograph Signer Protocol: base mode,
// single-shot, DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM
// (kem 0x0010, kdf 0x0001, aead 0x0002).
//
// Implemented over @noble primitives instead of WebCrypto so the SDK runs
// unmodified in React Native. AES-128-GCM (0x0001) is also supported purely
// so the RFC 9180 A.3 test vectors can exercise the KEM and key schedule.
//

import { p256 } from '@noble/curves/p256';
import { extract as hkdfExtract, expand as hkdfExpand } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';
import { gcm } from '@noble/ciphers/aes';
import { concatBytes, utf8Bytes } from './encoding.js';

const KEM_ID = 0x0010; // DHKEM(P-256, HKDF-SHA256)
const KDF_ID = 0x0001; // HKDF-SHA256
export const AEAD_AES_256_GCM = 0x0002;
export const AEAD_AES_128_GCM = 0x0001;

const MODE_BASE = 0x00;
const VERSION_LABEL = utf8Bytes('HPKE-v1');
export const ENCAPSULATED_KEY_LENGTH = 65; // uncompressed P-256 point

function i2osp(value: number, length: number): Uint8Array {
  const output = new Uint8Array(length);
  for (let i = length - 1; i >= 0; i -= 1) {
    output[i] = value & 0xff;
    value >>>= 8;
  }
  return output;
}

const KEM_SUITE_ID = concatBytes(utf8Bytes('KEM'), i2osp(KEM_ID, 2));

function hpkeSuiteId(aeadId: number): Uint8Array {
  return concatBytes(
    utf8Bytes('HPKE'),
    i2osp(KEM_ID, 2),
    i2osp(KDF_ID, 2),
    i2osp(aeadId, 2),
  );
}

function labeledExtract(
  suiteId: Uint8Array,
  salt: Uint8Array,
  label: string,
  ikm: Uint8Array,
): Uint8Array {
  return hkdfExtract(sha256, concatBytes(VERSION_LABEL, suiteId, utf8Bytes(label), ikm), salt);
}

function labeledExpand(
  suiteId: Uint8Array,
  prk: Uint8Array,
  label: string,
  info: Uint8Array,
  length: number,
): Uint8Array {
  const labeledInfo = concatBytes(
    i2osp(length, 2),
    VERSION_LABEL,
    suiteId,
    utf8Bytes(label),
    info,
  );
  return hkdfExpand(sha256, prk, labeledInfo, length);
}

/// DHKEM ExtractAndExpand (RFC 9180 §4.1).
function extractAndExpand(dh: Uint8Array, kemContext: Uint8Array): Uint8Array {
  const eaePrk = labeledExtract(KEM_SUITE_ID, new Uint8Array(0), 'eae_prk', dh);
  return labeledExpand(KEM_SUITE_ID, eaePrk, 'shared_secret', kemContext, 32);
}

/// ECDH over P-256 returning the raw x-coordinate (RFC 9180 §7.1.4… the
/// noble shared-secret output is a compressed point; strip the prefix byte).
function dh(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  return p256.getSharedSecret(privateKey, publicKey, true).subarray(1);
}

interface Schedule {
  key: Uint8Array;
  baseNonce: Uint8Array;
}

function keySchedule(
  aeadId: number,
  sharedSecret: Uint8Array,
  info: Uint8Array,
): Schedule {
  const suiteId = hpkeSuiteId(aeadId);
  const keyLength = aeadId === AEAD_AES_256_GCM ? 32 : 16;

  const pskIdHash = labeledExtract(suiteId, new Uint8Array(0), 'psk_id_hash', new Uint8Array(0));
  const infoHash = labeledExtract(suiteId, new Uint8Array(0), 'info_hash', info);
  const keyScheduleContext = concatBytes(i2osp(MODE_BASE, 1), pskIdHash, infoHash);
  const secret = labeledExtract(suiteId, sharedSecret, 'secret', new Uint8Array(0));

  return {
    key: labeledExpand(suiteId, secret, 'key', keyScheduleContext, keyLength),
    baseNonce: labeledExpand(suiteId, secret, 'base_nonce', keyScheduleContext, 12),
  };
}

export interface SealResult {
  /// Uncompressed ephemeral public key (65 bytes).
  encapsulatedKey: Uint8Array;
  /// Ciphertext including the 16-byte GCM tag.
  ciphertext: Uint8Array;
}

/// Single-shot base-mode seal. `ephemeralPrivateKey` is for test vectors
/// only — production callers omit it and get a fresh random key.
export function seal(
  recipientPublicKey: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
  options: { aeadId?: number; ephemeralPrivateKey?: Uint8Array } = {},
): SealResult {
  const aeadId = options.aeadId ?? AEAD_AES_256_GCM;
  const ephemeralPrivate = options.ephemeralPrivateKey ?? p256.utils.randomPrivateKey();
  const encapsulatedKey = p256.getPublicKey(ephemeralPrivate, false);

  const recipientUncompressed =
    p256.ProjectivePoint.fromHex(recipientPublicKey).toRawBytes(false);
  const sharedSecret = extractAndExpand(
    dh(ephemeralPrivate, recipientPublicKey),
    concatBytes(encapsulatedKey, recipientUncompressed),
  );
  const { key, baseNonce } = keySchedule(aeadId, sharedSecret, info);
  const ciphertext = gcm(key, baseNonce, aad).encrypt(plaintext);
  return { encapsulatedKey, ciphertext };
}

/// Single-shot base-mode open of `enc ‖ ct`.
export function open(
  recipientPrivateKey: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
  encapsulatedKey: Uint8Array,
  ciphertext: Uint8Array,
  options: { aeadId?: number } = {},
): Uint8Array {
  const aeadId = options.aeadId ?? AEAD_AES_256_GCM;
  if (encapsulatedKey.length !== ENCAPSULATED_KEY_LENGTH) {
    throw new Error('HPKE: bad encapsulated key length');
  }
  const recipientPublic = p256.getPublicKey(recipientPrivateKey, false);
  const sharedSecret = extractAndExpand(
    dh(recipientPrivateKey, encapsulatedKey),
    concatBytes(encapsulatedKey, recipientPublic),
  );
  const { key, baseNonce } = keySchedule(aeadId, sharedSecret, info);
  return gcm(key, baseNonce, aad).decrypt(ciphertext);
}
