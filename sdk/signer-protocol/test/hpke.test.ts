import { p256 } from '@noble/curves/p256';
import { AEAD_AES_128_GCM, open, seal } from '../src/hpke.js';
import { openBody, sealBody } from '../src/crypto.js';
import { generateKeyPair } from '../src/crypto.js';
import { utf8Bytes } from '../src/encoding.js';

function hex(text: string): Uint8Array {
  const bytes = new Uint8Array(text.length / 2);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = parseInt(text.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function toHex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

describe('HPKE base mode, DHKEM(P-256, HKDF-SHA256)', () => {
  // RFC 9180 Appendix A.3.1 (DHKEM(P-256, HKDF-SHA256), HKDF-SHA256,
  // AES-128-GCM, base mode) — validates the KEM and key schedule against
  // official vectors; our production AEAD (AES-256-GCM) differs only in the
  // aead_id and key length.
  const rfc = {
    info: hex('4f6465206f6e2061204772656369616e2055726e'),
    skEm: hex('4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb'),
    skRm: hex('f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2'),
    pkEm: hex(
      '04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4',
    ),
    pt: hex('4265617574792069732074727574682c20747275746820626561757479'),
    aad0: hex('436f756e742d30'),
    ct0: hex(
      '5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab2523f39513434',
    ),
  };

  test('matches RFC 9180 A.3.1 encryption vector', () => {
    const { encapsulatedKey, ciphertext } = seal(
      p256.getPublicKey(rfc.skRm, true),
      rfc.info,
      rfc.aad0,
      rfc.pt,
      { aeadId: AEAD_AES_128_GCM, ephemeralPrivateKey: rfc.skEm },
    );
    expect(toHex(encapsulatedKey)).toBe(toHex(rfc.pkEm));
    expect(toHex(ciphertext)).toBe(toHex(rfc.ct0));
  });

  test('matches RFC 9180 A.3.1 decryption', () => {
    const plaintext = open(rfc.skRm, rfc.info, rfc.aad0, rfc.pkEm, rfc.ct0, {
      aeadId: AEAD_AES_128_GCM,
    });
    expect(toHex(plaintext)).toBe(toHex(rfc.pt));
  });

  test('CSP body seal/open round trip (AES-256-GCM)', () => {
    const recipient = generateKeyPair();
    const plaintext = utf8Bytes('attack at dawn');
    const sealed = sealBody(plaintext, recipient.publicKey, 'sign_request', 'P1', 7);
    expect(sealed.length).toBe(65 + plaintext.length + 16);
    const opened = openBody(sealed, recipient.privateKey, 'sign_request', 'P1', 7);
    expect(opened).toEqual(plaintext);
  });

  test('AAD binding rejects transplanted bodies', () => {
    const recipient = generateKeyPair();
    const sealed = sealBody(utf8Bytes('payload'), recipient.publicKey, 'sign_request', 'P1', 7);
    expect(() => openBody(sealed, recipient.privateKey, 'sign_request', 'P1', 8)).toThrow();
    expect(() => openBody(sealed, recipient.privateKey, 'sign_response', 'P1', 7)).toThrow();
    expect(() => openBody(sealed, recipient.privateKey, 'sign_request', 'P2', 7)).toThrow();
    const other = generateKeyPair();
    expect(() => openBody(sealed, other.privateKey, 'sign_request', 'P1', 7)).toThrow();
  });
});
