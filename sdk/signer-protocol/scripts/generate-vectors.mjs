//
// Generates deterministic cross-implementation test vectors for the
// Cryptograph Signer Protocol. The TypeScript implementation produces them
// (noble ECDSA is deterministic per RFC 6979 and the HPKE ephemeral key is
// fixed); the Swift test suite (SignerProtocolVectorTests) consumes the
// byte-identical file and must verify/unseal everything.
//
// Run: npm run generate-vectors
// Output: test/vectors/cross_impl_vectors.json
//         ../../AppCore/Tests/AppCoreTests/SignerProtocolVectors.json (copy)
//

import { writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { p256 } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha2';

import {
  canonicalize,
} from '../dist/jcs.js';
import {
  makeEnvelope,
  canonicalEnvelope,
} from '../dist/envelope.js';
import {
  sign,
  signingInput,
  sealBody,
} from '../dist/crypto.js';
import { toBase64Url, utf8Bytes } from '../dist/encoding.js';
import { createPairRequest, createSignRequest } from '../dist/integrator.js';

const here = dirname(fileURLToPath(import.meta.url));

// Deterministic, obviously-non-production private scalars: sha256 of labels.
function fixedKey(label) {
  const scalar = sha256(utf8Bytes(`CSP test vectors 2026: ${label}`));
  if (!p256.utils.isValidPrivateKey(scalar)) throw new Error(`bad scalar for ${label}`);
  return scalar;
}

const NOW = 1782300000; // 2026-06-24T12:40:00Z — fixed protocol clock
const CALLBACK = 'https://links.rabby.example/cryptograph-callback';
const ACCOUNT = '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed';
const PAIRING_ID = '6BE2A38E-1111-4222-8333-444455556666';

const peerSig = fixedKey('peer signing');
const peerKem = fixedKey('peer kem');
const cgSig = fixedKey('cryptograph signing');
const cgKem = fixedKey('cryptograph kem');
const hpkeEphemeral = fixedKey('hpke ephemeral');
const nonce = sha256(utf8Bytes('CSP test vectors 2026: nonce'));

const vectors = { suite: 'CSP1', generated_by: '@perpetua/signer-protocol', jcs: [], signing: [], hpke: [], transcript: {} };

// 1. JCS canonicalization vectors.
for (const value of [
  { b: 2, a: 1, aa: 3, A: 0 },
  { z: [true, false, 'x'], a: { k: 7 } },
  { s: 'esc "quote" \\ tab\t nl\n μ→' },
  { neg: -42, big: 9007199254740991 },
  { nested: { deep: [{ x: 'y' }, [1, 2, 3]] } },
]) {
  vectors.jcs.push({ value, canonical: canonicalize(value) });
}

// 2. Signing-input vectors (deterministic RFC 6979 signatures — Swift must
//    VERIFY them; CryptoKit's own signatures are randomized).
for (const [type, host, fields] of [
  ['accounts_request', 'cryptograph.watch', { pairing_id: PAIRING_ID, ctr: 2, iat: NOW, exp: NOW + 300 }],
  ['revoke', 'links.rabby.example', { pairing_id: PAIRING_ID, ctr: 9, iat: NOW }],
]) {
  const envelope = makeEnvelope(type, fields);
  const canonical = canonicalEnvelope(envelope);
  const input = signingInput(type, host, canonical);
  vectors.signing.push({
    type,
    destination_host: host,
    envelope: envelope.fields,
    canonical,
    signing_input_utf8: `CSP1|${type}|${host}|${canonical}`,
    signer_public_key: toBase64Url(p256.getPublicKey(peerSig, true)),
    signature: toBase64Url(sign(input, peerSig)),
  });
}

// 3. HPKE seal vectors (fixed ephemeral): Swift opens with the recipient key.
for (const [plaintext, type, ctr] of [
  ['attack at dawn', 'sign_request', 7],
  ['{"request_id":"R1","result":{"signature":"0xabc"}}', 'sign_response', 3],
]) {
  vectors.hpke.push({
    recipient_kem_private_key: toBase64Url(cgKem),
    recipient_kem_public_key: toBase64Url(p256.getPublicKey(cgKem, true)),
    type,
    pairing_id: PAIRING_ID,
    ctr,
    plaintext_utf8: plaintext,
    sealed: toBase64Url(
      sealBody(utf8Bytes(plaintext), p256.getPublicKey(cgKem, true), type, PAIRING_ID, ctr, hpkeEphemeral),
    ),
  });
}

// 4. Full transcript: pair_request and sign_request URLs the Swift relay
//    engine must accept end to end.
const pair = createPairRequest(CALLBACK, 'Rabby', {
  now: () => NOW,
  generateKeys: (() => {
    // createPairRequest calls generateKeys twice: signing first, then KEM.
    const queue = [peerSig, peerKem];
    return () => {
      const privateKey = queue.shift();
      if (!privateKey) throw new Error('key queue exhausted');
      return { privateKey, publicKey: p256.getPublicKey(privateKey, true) };
    };
  })(),
  randomNonce: () => nonce,
});

const pairing = {
  pairingId: PAIRING_ID,
  callbackURL: CALLBACK,
  signingPrivateKey: toBase64Url(peerSig),
  kemPrivateKey: toBase64Url(peerKem),
  cryptographSigPub: toBase64Url(p256.getPublicKey(cgSig, true)),
  cryptographKemPub: toBase64Url(p256.getPublicKey(cgKem, true)),
  grants: { grants: [{ account: ACCOUNT, chains: ['eip155:1'] }], methods: ['eth_signTransaction', 'personal_sign', 'eth_signTypedData_v4'] },
  outboundCounter: 0,
  inboundCounter: 0,
};

const signRequest = createSignRequest(
  pairing,
  {
    requestId: '0E1FA0C4-7777-4888-9999-AAAABBBBCCCC',
    account: ACCOUNT,
    chain: 'eip155:1',
    method: 'eth_signTransaction',
    payload: {
      to: '0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D',
      value: '0xde0b6b3a7640000',
      data: '0x',
      nonce: '0x1',
      chainId: '0x1',
      gas: '0x5208',
      maxFeePerGas: '0x59682f00',
      maxPriorityFeePerGas: '0x3b9aca00',
    },
  },
  { now: () => NOW, hpkeEphemeralKey: () => hpkeEphemeral },
);

vectors.transcript = {
  relay_now: NOW,
  callback_url: CALLBACK,
  account: ACCOUNT,
  pairing_id: PAIRING_ID,
  peer_signing_private_key: toBase64Url(peerSig),
  peer_kem_private_key: toBase64Url(peerKem),
  peer_signing_public_key: toBase64Url(p256.getPublicKey(peerSig, true)),
  peer_kem_public_key: toBase64Url(p256.getPublicKey(peerKem, true)),
  cg_signing_private_key: toBase64Url(cgSig),
  cg_kem_private_key: toBase64Url(cgKem),
  pair_request_url: pair.url,
  sign_request_url: signRequest.url,
  sign_request_ctr: signRequest.pairing.outboundCounter,
  expected_sign_body: {
    request_id: '0E1FA0C4-7777-4888-9999-AAAABBBBCCCC',
    chain: 'eip155:1',
    method: 'eth_signTransaction',
  },
};

const json = JSON.stringify(vectors, null, 2) + '\n';
mkdirSync(join(here, '../test/vectors'), { recursive: true });
writeFileSync(join(here, '../test/vectors/cross_impl_vectors.json'), json);
writeFileSync(
  join(here, '../../../AppCore/Tests/AppCoreTests/SignerProtocolVectors.json'),
  json,
);
console.log('vectors written');
