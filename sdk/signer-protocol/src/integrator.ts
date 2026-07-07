//
// Integrator-side session for the Cryptograph Signer Protocol v1: build
// pair/accounts/sign request URLs and verify callback URLs. This is the
// wallet-facing API — a Rabby keyring wraps exactly these functions.
//
// State handling is deliberately explicit: every function returns the next
// pairing state and the caller persists it BEFORE opening the returned URL
// (counters must never be reused).
//

import {
  CSPProtocolError,
  MAX_SIGN_REQUEST_LIFETIME_SECONDS,
  RELAY_HOST,
  canonicalEnvelope,
  makeEnvelope,
  makeMessageURL,
  parseMessageURL,
  validateCallbackURL,
  type Envelope,
  type ErrorCode,
} from './envelope.js';
import { canonicalize, type CSPValue } from './jcs.js';
import {
  generateKeyPair,
  openBody,
  publicKeyFor,
  rotationProofInput,
  sealBody,
  sha256Bytes,
  sign,
  signingInput,
  verify,
} from './crypto.js';
import {
  bytesEqual,
  fromBase64Url,
  toBase64Url,
  utf8Bytes,
  utf8String,
} from './encoding.js';

// MARK: - Types

export interface Grant {
  account: string;
  chains: string[];
}

export interface GrantSet {
  grants: Grant[];
  methods: string[];
}

export interface PendingPair {
  signingPrivateKey: string; // base64url
  kemPrivateKey: string; // base64url
  callbackURL: string;
  noncePeer: string; // base64url
  requestHash: string; // base64url
  createdAt: number; // unix seconds
}

export interface Pairing {
  pairingId: string;
  callbackURL: string;
  signingPrivateKey: string; // base64url
  kemPrivateKey: string; // base64url
  cryptographSigPub: string; // base64url, pinned
  cryptographKemPub: string; // base64url, pinned
  grants: GrantSet;
  outboundCounter: number;
  inboundCounter: number;
}

export type SignMethod =
  | 'eth_signTransaction'
  | 'eth_sendTransaction'
  | 'personal_sign'
  | 'eth_signTypedData_v4';

export interface SignRequestContent {
  requestId: string;
  account: string;
  chain: string; // eip155:*
  method: SignMethod;
  payload: CSPValue;
}

export type SignResult =
  | { requestId: string; signedTransaction: string }
  | { requestId: string; signature: string }
  | { requestId: string; error: { code: ErrorCode; message: string } };

export type CallbackEvent =
  | { kind: 'accounts'; grants: GrantSet; pairing: Pairing }
  | { kind: 'sign'; result: SignResult; pairing: Pairing }
  | { kind: 'revoked'; pairing: Pairing }
  | { kind: 'keysRotated'; pairing: Pairing };

export type PairCallbackEvent =
  | { kind: 'paired'; pairing: Pairing }
  | { kind: 'declined' };

// MARK: - Injectable randomness/clock (tests + vector generation)

export interface SessionOptions {
  relayHost?: string;
  now?: () => number; // unix seconds
  randomUUID?: () => string;
  generateKeys?: () => { privateKey: Uint8Array; publicKey: Uint8Array };
  randomNonce?: () => Uint8Array;
  hpkeEphemeralKey?: () => Uint8Array | undefined;
}

function defaults(options: SessionOptions = {}) {
  return {
    relayHost: options.relayHost ?? RELAY_HOST,
    now: options.now ?? (() => Math.floor(Date.now() / 1000)),
    randomUUID:
      options.randomUUID ?? (() => globalThis.crypto.randomUUID().toUpperCase()),
    generateKeys: options.generateKeys ?? generateKeyPair,
    randomNonce:
      options.randomNonce ??
      (() => globalThis.crypto.getRandomValues(new Uint8Array(32))),
    hpkeEphemeralKey: options.hpkeEphemeralKey ?? (() => undefined),
  };
}

// MARK: - Pairing (§7)

export function createPairRequest(
  callbackURL: string,
  appName?: string,
  options: SessionOptions = {},
): { url: string; pending: PendingPair } {
  const config = defaults(options);
  validateCallbackURL(callbackURL);

  const signingKeys = config.generateKeys();
  const kemKeys = config.generateKeys();
  const nonce = config.randomNonce();
  const now = config.now();

  const fields: Record<string, CSPValue> = {
    cb: callbackURL,
    peer_sig_pub: toBase64Url(signingKeys.publicKey),
    peer_kem_pub: toBase64Url(kemKeys.publicKey),
    nonce_peer: toBase64Url(nonce),
    iat: now,
    exp: now + 600,
  };
  if (appName !== undefined) fields['app_name'] = appName;
  const envelope = makeEnvelope('pair_request', fields);
  const canonical = canonicalEnvelope(envelope);
  const signature = sign(
    signingInput('pair_request', config.relayHost, canonical),
    signingKeys.privateKey,
  );

  return {
    url: makeMessageURL(`https://${config.relayHost}/pair`, envelope, signature, false),
    pending: {
      signingPrivateKey: toBase64Url(signingKeys.privateKey),
      kemPrivateKey: toBase64Url(kemKeys.privateKey),
      callbackURL,
      noncePeer: toBase64Url(nonce),
      requestHash: toBase64Url(sha256Bytes(utf8Bytes(canonical))),
      createdAt: now,
    },
  };
}

export function handlePairCallback(
  url: string,
  pending: PendingPair,
): PairCallbackEvent {
  const message = parseCallbackMessage(url, pending.callbackURL);
  const { envelope } = message;
  if (envelope.type !== 'pair_response') {
    throw new CSPProtocolError('invalid_request', 'Expected pair_response');
  }
  const fields = envelope.fields;

  // Transcript binding (§7.3).
  if (
    fields['nonce_peer'] !== pending.noncePeer ||
    fields['req_hash'] !== pending.requestHash
  ) {
    throw new CSPProtocolError('invalid_signature', 'Pairing transcript mismatch');
  }

  const cgSigPub = requireBase64Field(fields, 'cg_sig_pub', 33);
  const callbackHost = new URL(pending.callbackURL).hostname.toLowerCase();
  const input = signingInput(
    'pair_response',
    callbackHost,
    canonicalEnvelope(envelope),
  );
  if (!verify(message.signature, input, cgSigPub)) {
    throw new CSPProtocolError('invalid_signature', 'pair_response signature failed');
  }

  if (fields['error'] === 'rejected_by_user') {
    return { kind: 'declined' };
  }

  const pairingId = fields['pairing_id'];
  const cgKemPub = requireBase64Field(fields, 'cg_kem_pub', 33);
  requireBase64Field(fields, 'nonce_cg', 32);
  const body = fields['body'];
  if (typeof pairingId !== 'string' || typeof body !== 'string') {
    throw new CSPProtocolError('invalid_request', 'Malformed pair_response');
  }

  const grantsBytes = openBody(
    fromBase64Url(body),
    fromBase64Url(pending.kemPrivateKey),
    'pair_response',
    pairingId,
    0,
  );
  const grants = decodeGrants(utf8String(grantsBytes));

  return {
    kind: 'paired',
    pairing: {
      pairingId,
      callbackURL: pending.callbackURL,
      signingPrivateKey: pending.signingPrivateKey,
      kemPrivateKey: pending.kemPrivateKey,
      cryptographSigPub: toBase64Url(cgSigPub),
      cryptographKemPub: toBase64Url(cgKemPub),
      grants,
      outboundCounter: 0,
      inboundCounter: 0,
    },
  };
}

// MARK: - Requests (§8, §9)

export function createAccountsRequest(
  pairing: Pairing,
  options: SessionOptions = {},
): { url: string; pairing: Pairing } {
  const config = defaults(options);
  const next = { ...pairing, outboundCounter: pairing.outboundCounter + 1 };
  const now = config.now();
  const envelope = makeEnvelope('accounts_request', {
    pairing_id: next.pairingId,
    ctr: next.outboundCounter,
    iat: now,
    exp: now + 300,
  });
  return {
    url: signedRequestURL(envelope, next, '/accounts', config.relayHost),
    pairing: next,
  };
}

export function createSignRequest(
  pairing: Pairing,
  content: SignRequestContent,
  options: SessionOptions & { lifetimeSeconds?: number } = {},
): { url: string; pairing: Pairing } {
  const config = defaults(options);
  const next = { ...pairing, outboundCounter: pairing.outboundCounter + 1 };

  const bodyObject: Record<string, CSPValue> = {
    request_id: content.requestId,
    account: content.account,
    chain: content.chain,
    method: content.method,
    payload: content.payload,
  };
  const sealed = sealBody(
    utf8Bytes(canonicalize(bodyObject)),
    fromBase64Url(next.cryptographKemPub),
    'sign_request',
    next.pairingId,
    next.outboundCounter,
    config.hpkeEphemeralKey(),
  );

  const now = config.now();
  const lifetime = Math.min(
    options.lifetimeSeconds ?? 300,
    MAX_SIGN_REQUEST_LIFETIME_SECONDS,
  );
  const envelope = makeEnvelope('sign_request', {
    pairing_id: next.pairingId,
    ctr: next.outboundCounter,
    iat: now,
    exp: now + lifetime,
    body: toBase64Url(sealed),
  });
  return {
    url: signedRequestURL(envelope, next, '/sign', config.relayHost),
    pairing: next,
  };
}

export function handleCallback(url: string, pairing: Pairing): CallbackEvent {
  const message = parseCallbackMessage(url, pairing.callbackURL);
  const { envelope } = message;
  const fields = envelope.fields;

  if (fields['pairing_id'] !== pairing.pairingId) {
    throw new CSPProtocolError('unknown_pairing', 'Callback for a different pairing');
  }
  const callbackHost = new URL(pairing.callbackURL).hostname.toLowerCase();
  const input = signingInput(envelope.type, callbackHost, canonicalEnvelope(envelope));
  if (!verify(message.signature, input, fromBase64Url(pairing.cryptographSigPub))) {
    throw new CSPProtocolError('invalid_signature', 'Callback signature failed');
  }
  const counter = fields['ctr'];
  if (typeof counter !== 'number' || counter <= pairing.inboundCounter) {
    throw new CSPProtocolError('counter_replayed', 'Callback counter replayed');
  }
  const next = { ...pairing, inboundCounter: counter };

  switch (envelope.type) {
    case 'accounts_response': {
      const grants = decodeGrants(
        utf8String(unsealCallbackBody(fields, next, envelope.type, counter)),
      );
      return { kind: 'accounts', grants, pairing: { ...next, grants } };
    }
    case 'sign_response': {
      const bodyText = utf8String(unsealCallbackBody(fields, next, envelope.type, counter));
      return { kind: 'sign', result: decodeSignResult(bodyText), pairing: next };
    }
    case 'revoke':
      return { kind: 'revoked', pairing: next };
    case 'rotate_key': {
      const bodyText = utf8String(unsealCallbackBody(fields, next, envelope.type, counter));
      const body = JSON.parse(bodyText) as Record<string, unknown>;
      const newSigPub =
        typeof body['new_sig_pub'] === 'string' ? fromBase64Url(body['new_sig_pub']) : undefined;
      const newKemPub =
        typeof body['new_kem_pub'] === 'string' ? fromBase64Url(body['new_kem_pub']) : undefined;
      const proof =
        typeof body['proof'] === 'string' ? fromBase64Url(body['proof']) : undefined;
      if ((!newSigPub && !newKemPub) || !proof) {
        throw new CSPProtocolError('invalid_request', 'Malformed rotate_key body');
      }
      const proofInput = rotationProofInput(
        next.pairingId,
        counter,
        newSigPub,
        newKemPub,
        toBase64Url,
      );
      const proofKey = newSigPub ?? fromBase64Url(next.cryptographSigPub);
      if (!verify(proof, proofInput, proofKey)) {
        throw new CSPProtocolError('invalid_signature', 'Rotation proof failed');
      }
      return {
        kind: 'keysRotated',
        pairing: {
          ...next,
          cryptographSigPub: newSigPub ? toBase64Url(newSigPub) : next.cryptographSigPub,
          cryptographKemPub: newKemPub ? toBase64Url(newKemPub) : next.cryptographKemPub,
        },
      };
    }
    default:
      throw new CSPProtocolError('invalid_request', `Unexpected callback type ${envelope.type}`);
  }
}

// MARK: - Helpers

function parseCallbackMessage(url: string, expectedCallback: string) {
  const expected = new URL(expectedCallback);
  const actual = new URL(url);
  if (
    actual.hostname.toLowerCase() !== expected.hostname.toLowerCase() ||
    actual.pathname !== expected.pathname
  ) {
    throw new CSPProtocolError('invalid_request', 'Callback host/path mismatch');
  }
  const message = parseMessageURL(url);
  if (!message.isResponse) {
    throw new CSPProtocolError('invalid_request', 'Expected res parameter');
  }
  return message;
}

function signedRequestURL(
  envelope: Envelope,
  pairing: Pairing,
  path: string,
  relayHost: string,
): string {
  const signature = sign(
    signingInput(envelope.type, relayHost, canonicalEnvelope(envelope)),
    fromBase64Url(pairing.signingPrivateKey),
  );
  return makeMessageURL(`https://${relayHost}${path}`, envelope, signature, false);
}

function unsealCallbackBody(
  fields: Record<string, CSPValue>,
  pairing: Pairing,
  type: MessageTypeWithBody,
  counter: number,
): Uint8Array {
  const body = fields['body'];
  if (typeof body !== 'string') {
    throw new CSPProtocolError('invalid_request', 'Missing body');
  }
  try {
    return openBody(
      fromBase64Url(body),
      fromBase64Url(pairing.kemPrivateKey),
      type,
      pairing.pairingId,
      counter,
    );
  } catch {
    throw new CSPProtocolError('decode_failed', 'Body did not unseal');
  }
}

type MessageTypeWithBody = 'accounts_response' | 'sign_response' | 'rotate_key';

function requireBase64Field(
  fields: Record<string, CSPValue>,
  key: string,
  length: number,
): Uint8Array {
  const value = fields[key];
  if (typeof value !== 'string') {
    throw new CSPProtocolError('invalid_request', `Missing field ${key}`);
  }
  const bytes = fromBase64Url(value);
  if (bytes.length !== length) {
    throw new CSPProtocolError('invalid_request', `Field ${key} has wrong length`);
  }
  return bytes;
}

function decodeGrants(text: string): GrantSet {
  const object = JSON.parse(text) as Record<string, unknown>;
  const rawGrants = object['grants'];
  const rawMethods = object['methods'];
  if (!Array.isArray(rawGrants) || !Array.isArray(rawMethods)) {
    throw new CSPProtocolError('invalid_request', 'Malformed grants body');
  }
  const grants: Grant[] = rawGrants.map((entry) => {
    const record = entry as Record<string, unknown>;
    if (typeof record['account'] !== 'string' || !Array.isArray(record['chains'])) {
      throw new CSPProtocolError('invalid_request', 'Malformed grant entry');
    }
    return {
      account: record['account'],
      chains: record['chains'].filter((chain): chain is string => typeof chain === 'string'),
    };
  });
  return {
    grants,
    methods: rawMethods.filter((method): method is string => typeof method === 'string'),
  };
}

function decodeSignResult(text: string): SignResult {
  const object = JSON.parse(text) as Record<string, unknown>;
  const requestId = object['request_id'];
  if (typeof requestId !== 'string') {
    throw new CSPProtocolError('invalid_request', 'Missing request_id');
  }
  const result = object['result'] as Record<string, unknown> | undefined;
  if (result) {
    if (typeof result['signedTransaction'] === 'string') {
      return { requestId, signedTransaction: result['signedTransaction'] };
    }
    if (typeof result['signature'] === 'string') {
      return { requestId, signature: result['signature'] };
    }
    throw new CSPProtocolError('invalid_request', 'Malformed result');
  }
  const error = object['error'] as Record<string, unknown> | undefined;
  if (error && typeof error['code'] === 'string') {
    return {
      requestId,
      error: {
        code: error['code'] as ErrorCode,
        message: typeof error['message'] === 'string' ? error['message'] : '',
      },
    };
  }
  throw new CSPProtocolError('invalid_request', 'Neither result nor error present');
}
