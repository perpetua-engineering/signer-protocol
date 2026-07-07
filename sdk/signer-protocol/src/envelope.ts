//
// CSP v1 envelope model, strict shape validation, and URL codec (§2.4, §5).
// Mirrors the Swift implementation byte for byte.
//

import { canonicalize, parseProfile, type CSPValue } from './jcs.js';
import { fromBase64Url, toBase64Url, utf8Bytes, utf8String } from './encoding.js';

export const PROTOCOL_VERSION = 1;
export const RELAY_HOST = 'cryptograph.watch';
export const MAX_URL_BYTES = 65_536;
export const MAX_ENVELOPE_BYTES = 49_152;
export const MAX_SIGN_REQUEST_LIFETIME_SECONDS = 600;

export type MessageType =
  | 'pair_request'
  | 'pair_response'
  | 'accounts_request'
  | 'accounts_response'
  | 'sign_request'
  | 'sign_response'
  | 'revoke'
  | 'rotate_key';

export type ErrorCode =
  | 'invalid_request'
  | 'unsupported_version'
  | 'unknown_pairing'
  | 'revoked'
  | 'invalid_signature'
  | 'counter_replayed'
  | 'expired'
  | 'grant_violation'
  | 'unsupported_method'
  | 'payload_too_large'
  | 'decode_failed'
  | 'rejected_by_user'
  | 'timeout'
  | 'busy'
  | 'rate_limited'
  | 'internal_error';

export class CSPProtocolError extends Error {
  constructor(
    readonly code: ErrorCode,
    message: string,
  ) {
    super(`${code}: ${message}`);
    this.name = 'CSPProtocolError';
  }
}

interface FieldRules {
  required: string[];
  optional: string[];
}

const FIELD_RULES: Record<MessageType, FieldRules> = {
  pair_request: {
    required: ['cb', 'peer_sig_pub', 'peer_kem_pub', 'nonce_peer', 'iat', 'exp'],
    optional: ['app_name'],
  },
  pair_response: {
    required: ['nonce_peer', 'req_hash', 'cg_sig_pub', 'iat'],
    optional: ['pairing_id', 'cg_kem_pub', 'nonce_cg', 'body', 'error'],
  },
  accounts_request: {
    required: ['pairing_id', 'ctr', 'iat', 'exp'],
    optional: [],
  },
  accounts_response: {
    required: ['pairing_id', 'ctr', 'iat', 'body'],
    optional: [],
  },
  sign_request: {
    required: ['pairing_id', 'ctr', 'iat', 'exp', 'body'],
    optional: [],
  },
  sign_response: {
    required: ['pairing_id', 'ctr', 'iat', 'body'],
    optional: [],
  },
  revoke: {
    required: ['pairing_id', 'ctr', 'iat'],
    optional: ['exp'],
  },
  rotate_key: {
    required: ['pairing_id', 'ctr', 'iat', 'body'],
    optional: ['exp'],
  },
};

export interface Envelope {
  type: MessageType;
  fields: Record<string, CSPValue>;
}

export function makeEnvelope(
  type: MessageType,
  fields: Record<string, CSPValue>,
): Envelope {
  const object: Record<string, CSPValue> = { ...fields, v: PROTOCOL_VERSION, type };
  validateShape(object);
  return { type, fields: object };
}

export function canonicalEnvelope(envelope: Envelope): string {
  return canonicalize(envelope.fields);
}

function validateShape(object: Record<string, CSPValue>): void {
  const version = object['v'];
  if (typeof version !== 'number') {
    throw new CSPProtocolError('invalid_request', 'Missing version');
  }
  if (version !== PROTOCOL_VERSION) {
    throw new CSPProtocolError('unsupported_version', `Unsupported version ${version}`);
  }
  const type = object['type'];
  if (typeof type !== 'string' || !(type in FIELD_RULES)) {
    throw new CSPProtocolError('invalid_request', 'Unknown message type');
  }
  const rules = FIELD_RULES[type as MessageType];
  const present = Object.keys(object).filter((key) => key !== 'v' && key !== 'type');
  const missing = rules.required.filter((key) => !present.includes(key));
  if (missing.length > 0) {
    throw new CSPProtocolError('invalid_request', `Missing fields: ${missing.join(', ')}`);
  }
  const unknown = present.filter(
    (key) => !rules.required.includes(key) && !rules.optional.includes(key),
  );
  if (unknown.length > 0) {
    throw new CSPProtocolError('invalid_request', `Unknown fields: ${unknown.join(', ')}`);
  }
  for (const key of ['ctr', 'iat', 'exp']) {
    const value = object[key];
    if (value !== undefined && (typeof value !== 'number' || value < 0)) {
      throw new CSPProtocolError('invalid_request', `Field ${key} must be a non-negative integer`);
    }
  }
}

export interface ParsedMessage {
  envelope: Envelope;
  signature: Uint8Array;
  isResponse: boolean;
}

export function makeMessageURL(
  base: string,
  envelope: Envelope,
  signature: Uint8Array,
  asResponse: boolean,
): string {
  const canonical = canonicalEnvelope(envelope);
  const parameter = asResponse ? 'res' : 'req';
  const url =
    `${base}?${parameter}=${toBase64Url(utf8Bytes(canonical))}` +
    `&sig=${toBase64Url(signature)}`;
  if (utf8Bytes(url).length > MAX_URL_BYTES) {
    throw new CSPProtocolError('payload_too_large', `Message URL exceeds ${MAX_URL_BYTES} bytes`);
  }
  return url;
}

export function parseMessageURL(url: string): ParsedMessage {
  if (utf8Bytes(url).length > MAX_URL_BYTES) {
    throw new CSPProtocolError('payload_too_large', `Message URL exceeds ${MAX_URL_BYTES} bytes`);
  }
  const parsed = new URL(url);
  let envelopeEncoded: string | undefined;
  let signatureEncoded: string | undefined;
  let isResponse = false;
  for (const [key, value] of parsed.searchParams) {
    if (key === 'req') {
      envelopeEncoded = value;
      isResponse = false;
    } else if (key === 'res') {
      envelopeEncoded = value;
      isResponse = true;
    } else if (key === 'sig') {
      signatureEncoded = value;
    } else {
      throw new CSPProtocolError('invalid_request', `Unexpected query parameter ${key}`);
    }
  }
  if (!envelopeEncoded || !signatureEncoded) {
    throw new CSPProtocolError('invalid_request', 'Missing req/res or sig parameter');
  }
  const signature = fromBase64Url(signatureEncoded);
  if (signature.length !== 64) {
    throw new CSPProtocolError('invalid_request', 'Malformed signature');
  }
  const envelopeBytes = fromBase64Url(envelopeEncoded);
  if (envelopeBytes.length > MAX_ENVELOPE_BYTES) {
    throw new CSPProtocolError('payload_too_large', `Envelope exceeds ${MAX_ENVELOPE_BYTES} bytes`);
  }
  let object: CSPValue;
  try {
    object = parseProfile(utf8String(envelopeBytes));
  } catch (error) {
    throw new CSPProtocolError('invalid_request', `Envelope is not valid CSP1 JSON: ${error}`);
  }
  if (typeof object !== 'object' || object === null || Array.isArray(object)) {
    throw new CSPProtocolError('invalid_request', 'Envelope must be an object');
  }
  const record = object as Record<string, CSPValue>;
  validateShape(record);
  return {
    envelope: { type: record['type'] as MessageType, fields: record },
    signature,
    isResponse,
  };
}

/// §7.1 callback-URL rules. Returns the lowercase host (the peer domain).
export function validateCallbackURL(callback: string): string {
  let parsed: URL;
  try {
    parsed = new URL(callback);
  } catch {
    throw new CSPProtocolError('invalid_request', 'Callback URL does not parse');
  }
  const host = parsed.hostname.toLowerCase();
  if (
    parsed.protocol !== 'https:' ||
    parsed.search !== '' ||
    parsed.hash !== '' ||
    parsed.username !== '' ||
    parsed.password !== '' ||
    parsed.port !== '' ||
    !host.includes('.') ||
    !/^[a-z0-9.-]+$/.test(host) ||
    host.split('.').every((label) => /^\d+$/.test(label)) ||
    // The relay host itself can never be an integrator identity. Subdomains
    // are allowed — only the relay operator can associate apps with them.
    host === RELAY_HOST
  ) {
    throw new CSPProtocolError('invalid_request', 'Callback URL fails §7.1 rules');
  }
  return host;
}
