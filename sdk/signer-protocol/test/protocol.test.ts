//
// Protocol-level tests: envelope shape, URL codec, callback validation, and
// an integrator round trip against a minimal in-test relay implementation
// (the real counterpart implementation lives in the Cryptograph iOS app and
// is covered by byte-identical cross-implementation fixtures).
//

import {
  CSPProtocolError,
  canonicalEnvelope,
  makeEnvelope,
  makeMessageURL,
  parseMessageURL,
  validateCallbackURL,
} from '../src/envelope.js';
import {
  createPairRequest,
  createSignRequest,
  handleCallback,
  handlePairCallback,
  type GrantSet,
} from '../src/integrator.js';
import {
  generateKeyPair,
  openBody,
  sealBody,
  sha256Bytes,
  sign,
  signingInput,
  verify,
} from '../src/crypto.js';
import { fromBase64Url, toBase64Url, utf8Bytes, utf8String } from '../src/encoding.js';
import { canonicalize, type CSPValue } from '../src/jcs.js';

const CALLBACK = 'https://links.rabby.example/cryptograph-callback';
const ACCOUNT = '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed';

describe('envelope shape', () => {
  const base = {
    pairing_id: 'P1',
    ctr: 1,
    iat: 1782300000,
    exp: 1782300300,
    body: 'AAAA',
  };

  test('canonical form is byte-exact', () => {
    const envelope = makeEnvelope('accounts_request', {
      pairing_id: 'P1',
      ctr: 2,
      iat: 100,
      exp: 200,
    });
    expect(canonicalEnvelope(envelope)).toBe(
      '{"ctr":2,"exp":200,"iat":100,"pairing_id":"P1","type":"accounts_request","v":1}',
    );
  });

  test('unknown fields rejected', () => {
    expect(() => makeEnvelope('sign_request', { ...base, extra: 'x' })).toThrow(CSPProtocolError);
  });

  test('missing required fields rejected', () => {
    const { ctr: _ctr, ...withoutCtr } = base;
    expect(() => makeEnvelope('sign_request', withoutCtr)).toThrow(CSPProtocolError);
  });

  test('negative counters rejected', () => {
    expect(() => makeEnvelope('sign_request', { ...base, ctr: -1 })).toThrow(CSPProtocolError);
  });

  test('URL codec round trip and smuggled parameter rejection', () => {
    const envelope = makeEnvelope('sign_request', base);
    const signature = new Uint8Array(64).fill(0x42);
    const url = makeMessageURL('https://cryptograph.watch/sign', envelope, signature, false);
    const parsed = parseMessageURL(url);
    expect(parsed.isResponse).toBe(false);
    expect(canonicalEnvelope(parsed.envelope)).toBe(canonicalEnvelope(envelope));
    expect(parsed.signature).toEqual(signature);
    expect(() => parseMessageURL(url + '&evil=1')).toThrow(CSPProtocolError);
  });

  test('callback URL rules (§7.1)', () => {
    expect(validateCallbackURL(CALLBACK)).toBe('links.rabby.example');
    for (const bad of [
      'http://links.rabby.example/cb',
      'https://links.rabby.example/cb?x=1',
      'https://links.rabby.example/cb#frag',
      'https://localhost/cb',
      'https://127.0.0.1/cb',
      'https://links.rabby.example:8443/cb',
      'https://cryptograph.watch/cb',
    ]) {
      expect(() => validateCallbackURL(bad)).toThrow(CSPProtocolError);
    }
    // Relay-host subdomains are reserved for first-party demo integrators.
    expect(validateCallbackURL('https://demo.cryptograph.watch/cb')).toBe('demo.cryptograph.watch');
  });
});

describe('signatures', () => {
  test('destination-host binding', () => {
    const keys = generateKeyPair();
    const input = signingInput('sign_request', 'cryptograph.watch', '{"v":1}');
    const signature = sign(input, keys.privateKey);
    expect(signature.length).toBe(64);
    expect(verify(signature, input, keys.publicKey)).toBe(true);
    const otherHost = signingInput('sign_request', 'evil.example', '{"v":1}');
    expect(verify(signature, otherHost, keys.publicKey)).toBe(false);
  });
});

// A minimal relay stand-in: accepts the pair request, returns grants, and
// answers one sign request. Mirrors CSPRelayEngine's outbound message
// construction so the integrator functions get realistic inputs.
class MiniRelay {
  keys = { sig: generateKeyPair(), kem: generateKeyPair() };
  pairingId = '6BE2A38E-0000-4000-8000-000000000001';
  peerSigPub!: Uint8Array;
  peerKemPub!: Uint8Array;
  callback!: string;
  outboundCounter = 0;

  acceptPair(url: string, grants: GrantSet): string {
    const message = parseMessageURL(url);
    const fields = message.envelope.fields;
    this.callback = fields['cb'] as string;
    this.peerSigPub = fromBase64Url(fields['peer_sig_pub'] as string);
    this.peerKemPub = fromBase64Url(fields['peer_kem_pub'] as string);
    const input = signingInput('pair_request', 'cryptograph.watch', canonicalEnvelope(message.envelope));
    if (!verify(message.signature, input, this.peerSigPub)) {
      throw new Error('pair_request proof failed');
    }

    const sealedGrants = sealBody(
      utf8Bytes(canonicalize(grants as unknown as CSPValue)),
      this.peerKemPub,
      'pair_response',
      this.pairingId,
      0,
    );
    const envelope = makeEnvelope('pair_response', {
      pairing_id: this.pairingId,
      cg_sig_pub: toBase64Url(this.keys.sig.publicKey),
      cg_kem_pub: toBase64Url(this.keys.kem.publicKey),
      nonce_peer: fields['nonce_peer'] as string,
      nonce_cg: toBase64Url(new Uint8Array(32).fill(7)),
      req_hash: toBase64Url(sha256Bytes(utf8Bytes(canonicalEnvelope(message.envelope)))),
      iat: 1782300042,
      body: toBase64Url(sealedGrants),
    });
    return this.signedCallbackURL(envelope);
  }

  answerSign(url: string, kemPrivateKey: Uint8Array): string {
    const message = parseMessageURL(url);
    const fields = message.envelope.fields;
    const counter = fields['ctr'] as number;
    const input = signingInput('sign_request', 'cryptograph.watch', canonicalEnvelope(message.envelope));
    if (!verify(message.signature, input, this.peerSigPub)) {
      throw new Error('sign_request signature failed');
    }
    const body = JSON.parse(
      utf8String(
        openBody(fromBase64Url(fields['body'] as string), kemPrivateKey, 'sign_request', this.pairingId, counter),
      ),
    ) as { request_id: string };

    this.outboundCounter += 1;
    const responseBody = {
      request_id: body.request_id,
      result: { signedTransaction: '0x02f870deadbeef' },
    };
    const sealed = sealBody(
      utf8Bytes(canonicalize(responseBody)),
      this.peerKemPub,
      'sign_response',
      this.pairingId,
      this.outboundCounter,
    );
    const envelope = makeEnvelope('sign_response', {
      pairing_id: this.pairingId,
      ctr: this.outboundCounter,
      iat: 1782300100,
      body: toBase64Url(sealed),
    });
    return this.signedCallbackURL(envelope);
  }

  private signedCallbackURL(envelope: ReturnType<typeof makeEnvelope>): string {
    const host = new URL(this.callback).hostname;
    const signature = sign(
      signingInput(envelope.type, host, canonicalEnvelope(envelope)),
      this.keys.sig.privateKey,
    );
    return makeMessageURL(this.callback, envelope, signature, true);
  }
}

describe('integrator round trip', () => {
  const grants: GrantSet = {
    grants: [{ account: ACCOUNT, chains: ['eip155:1'] }],
    methods: ['eth_signTransaction', 'personal_sign', 'eth_signTypedData_v4'],
  };

  test('pair → sign → response', () => {
    const relay = new MiniRelay();
    const { url: pairUrl, pending } = createPairRequest(CALLBACK, 'Rabby');
    const callbackUrl = relay.acceptPair(pairUrl, grants);

    const paired = handlePairCallback(callbackUrl, pending);
    expect(paired.kind).toBe('paired');
    if (paired.kind !== 'paired') return;
    expect(paired.pairing.grants.grants[0]!.account).toBe(ACCOUNT);

    // The relay must hold the KEM private key matching cg_kem_pub — hand the
    // mini relay the integrator's view for the unseal (test-only shortcut:
    // in production the relay unseals with its own stored key).
    const { url: signUrl, pairing: afterSend } = createSignRequest(paired.pairing, {
      requestId: '0E1FA0C4-0000-4000-8000-000000000002',
      account: ACCOUNT,
      chain: 'eip155:1',
      method: 'eth_signTransaction',
      payload: {
        to: '0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D',
        value: '0x0',
        data: '0x',
        nonce: '0x1',
        chainId: '0x1',
        gas: '0x5208',
        maxFeePerGas: '0x59682f00',
        maxPriorityFeePerGas: '0x3b9aca00',
      },
    });
    expect(afterSend.outboundCounter).toBe(1);

    const signCallback = relay.answerSign(signUrl, relay.keys.kem.privateKey);
    const event = handleCallback(signCallback, afterSend);
    expect(event.kind).toBe('sign');
    if (event.kind !== 'sign') return;
    expect('signedTransaction' in event.result && event.result.signedTransaction).toBe(
      '0x02f870deadbeef',
    );
    expect(event.pairing.inboundCounter).toBe(1);

    // Replay must be rejected.
    expect(() => handleCallback(signCallback, event.pairing)).toThrow(/counter_replayed/);
  });

  test('declined pairing', () => {
    const relay = new MiniRelay();
    const { url: pairUrl, pending } = createPairRequest(CALLBACK);
    const message = parseMessageURL(pairUrl);
    const declineKeys = generateKeyPair();
    const envelope = makeEnvelope('pair_response', {
      cg_sig_pub: toBase64Url(declineKeys.publicKey),
      nonce_peer: message.envelope.fields['nonce_peer']!,
      req_hash: toBase64Url(sha256Bytes(utf8Bytes(canonicalEnvelope(message.envelope)))),
      error: 'rejected_by_user',
      iat: 1782300042,
    });
    const host = new URL(CALLBACK).hostname;
    const signature = sign(
      signingInput('pair_response', host, canonicalEnvelope(envelope)),
      declineKeys.privateKey,
    );
    const url = makeMessageURL(CALLBACK, envelope, signature, true);
    expect(handlePairCallback(url, pending)).toEqual({ kind: 'declined' });
    void relay;
  });

  test('tampered callback envelope is rejected', () => {
    const relay = new MiniRelay();
    const { url: pairUrl, pending } = createPairRequest(CALLBACK);
    const callbackUrl = relay.acceptPair(pairUrl, grants);
    const tampered = callbackUrl.replace(/res=[^&]+/, (match) => {
      const bytes = fromBase64Url(match.slice(4));
      const json = JSON.parse(utf8String(bytes)) as Record<string, unknown>;
      json['pairing_id'] = 'HIJACKED';
      return 'res=' + toBase64Url(utf8Bytes(canonicalize(json as CSPValue)));
    });
    expect(() => handlePairCallback(tampered, pending)).toThrow(CSPProtocolError);
  });
});
