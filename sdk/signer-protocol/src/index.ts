//
// @perpetua/signer-protocol — TypeScript SDK for the Cryptograph Signer
// Protocol v1. Spec: https://cryptograph.watch/signer-protocol
//
// Quick start (wallet side):
//
//   import { createPairRequest, handlePairCallback, createSignRequest,
//            handleCallback } from '@perpetua/signer-protocol';
//
//   // 1. Pair (opens the Cryptograph app):
//   const { url, pending } = createPairRequest(
//     'https://links.yourwallet.example/cryptograph-callback', 'YourWallet');
//   await Linking.openURL(url);            // persist `pending` first!
//
//   // 2. In your Universal Link handler for the callback URL:
//   const event = handlePairCallback(callbackUrl, pending);
//   if (event.kind === 'paired') persist(event.pairing);
//
//   // 3. Request a signature (approved on the user's Apple Watch):
//   const { url: signUrl, pairing: next } = createSignRequest(pairing, {
//     requestId: uuid(), account, chain: 'eip155:1',
//     method: 'eth_signTransaction', payload: tx,
//   });
//   persist(next);                          // BEFORE opening — counters!
//   await Linking.openURL(signUrl);
//
//   // 4. Handle the signed callback:
//   const result = handleCallback(callbackUrl, next);
//

export {
  createPairRequest,
  handlePairCallback,
  createAccountsRequest,
  createSignRequest,
  handleCallback,
} from './integrator.js';
export type {
  CallbackEvent,
  Grant,
  GrantSet,
  PairCallbackEvent,
  Pairing,
  PendingPair,
  SessionOptions,
  SignMethod,
  SignRequestContent,
  SignResult,
} from './integrator.js';

export {
  CSPProtocolError,
  MAX_ENVELOPE_BYTES,
  MAX_URL_BYTES,
  PROTOCOL_VERSION,
  RELAY_HOST,
  makeEnvelope,
  canonicalEnvelope,
  makeMessageURL,
  parseMessageURL,
  validateCallbackURL,
} from './envelope.js';
export type { Envelope, ErrorCode, MessageType, ParsedMessage } from './envelope.js';

export { canonicalize, parseProfile, assertProfile } from './jcs.js';
export type { CSPValue } from './jcs.js';

export {
  generateKeyPair,
  publicKeyFor,
  sign,
  verify,
  signingInput,
  sealBody,
  openBody,
} from './crypto.js';
export type { KeyPair } from './crypto.js';

export { toBase64Url, fromBase64Url } from './encoding.js';
