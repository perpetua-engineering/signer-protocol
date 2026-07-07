//
// Byte/string encoding helpers for the Cryptograph Signer Protocol.
// base64url per RFC 4648 §5, no padding. Pure JS — no Buffer, no WebCrypto —
// so the SDK runs unmodified in React Native, browsers, and Node.
//

const BASE64URL_ALPHABET =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

const BASE64URL_LOOKUP: Record<string, number> = Object.fromEntries(
  [...BASE64URL_ALPHABET].map((char, index) => [char, index]),
);

export function toBase64Url(bytes: Uint8Array): string {
  let output = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i]!;
    const b1 = bytes[i + 1];
    const b2 = bytes[i + 2];
    output += BASE64URL_ALPHABET[b0 >> 2]!;
    output += BASE64URL_ALPHABET[((b0 & 0x03) << 4) | ((b1 ?? 0) >> 4)]!;
    if (b1 === undefined) break;
    output += BASE64URL_ALPHABET[((b1 & 0x0f) << 2) | ((b2 ?? 0) >> 6)]!;
    if (b2 === undefined) break;
    output += BASE64URL_ALPHABET[b2 & 0x3f]!;
  }
  return output;
}

export function fromBase64Url(text: string): Uint8Array {
  if (!/^[A-Za-z0-9\-_]*$/.test(text)) {
    throw new Error('Invalid base64url input');
  }
  const remainder = text.length % 4;
  if (remainder === 1) throw new Error('Invalid base64url length');
  const byteLength = Math.floor((text.length * 3) / 4);
  const bytes = new Uint8Array(byteLength);
  let byteIndex = 0;
  for (let i = 0; i < text.length; i += 4) {
    const c0 = BASE64URL_LOOKUP[text[i]!]!;
    const c1 = BASE64URL_LOOKUP[text[i + 1]!];
    const c2 = text[i + 2] !== undefined ? BASE64URL_LOOKUP[text[i + 2]!] : undefined;
    const c3 = text[i + 3] !== undefined ? BASE64URL_LOOKUP[text[i + 3]!] : undefined;
    if (c1 === undefined) throw new Error('Invalid base64url input');
    bytes[byteIndex++] = (c0 << 2) | (c1 >> 4);
    if (c2 === undefined) continue;
    bytes[byteIndex++] = ((c1 & 0x0f) << 4) | (c2 >> 2);
    if (c3 === undefined) continue;
    bytes[byteIndex++] = ((c2 & 0x03) << 6) | c3;
  }
  return bytes.subarray(0, byteIndex);
}

export function utf8Bytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

export function utf8String(bytes: Uint8Array): string {
  return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
}

export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((sum, array) => sum + array.length, 0);
  const output = new Uint8Array(total);
  let offset = 0;
  for (const array of arrays) {
    output.set(array, offset);
    offset += array.length;
  }
  return output;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}
