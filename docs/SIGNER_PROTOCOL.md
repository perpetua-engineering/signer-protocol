# Cryptograph Signer Protocol (CSP) — Version 1

Status: **Draft for audit** · Published rendering: https://cryptograph.watch/signer-protocol
Canonical source: `docs/SIGNER_PROTOCOL.md` · Test vectors: `AppCore/Tests/AppCoreTests/Fixtures/SignerProtocol/`

The Cryptograph Signer Protocol lets any iOS wallet app request EVM signatures
from the Cryptograph watch-side signer without holding the user's keys, without
a relay server, and without per-app approval from Perpetua. It is a
domain-authenticated, mutually-authenticated request/response protocol carried
entirely over Universal Links between two apps on the same iPhone.

```
Integrator app (e.g. Rabby)
    │  https://cryptograph.watch/sign?req=…&sig=…      (Universal Link)
    ▼
Cryptograph iPhone app        — validates, decrypts, enforces grants
    │  WCSession (existing attested signing path)
    ▼
Cryptograph Watch app         — displays request + peer domain, user approves,
    │                            Secure Enclave-guarded key signs
    ▼
Cryptograph iPhone app
    │  https://<integrator-domain>/<callback>?res=…&sig=…   (Universal Link)
    ▼
Integrator app
```

Design goals, in priority order:

1. **The integrator never touches Cryptograph key material.** All signing
   happens on the watch after on-watch display and approval.
2. **No cloud intermediary.** Both legs are local app-to-app Universal Links.
3. **Permissionless.** Any app that owns a Universal-Link domain can integrate.
   There is no registry and no Perpetua-side allowlist.
4. **Domain-bound identity.** Each side is identified by a DNS domain proven by
   Apple's Universal-Link association (AASA), not by self-asserted metadata.
5. **Auditable.** Small surface, standard primitives (P-256 ECDSA, RFC 9180
   HPKE, RFC 8785 JCS), explicit test vectors.

## 1. Terminology and roles

- **Integrator** (also *peer*): the third-party wallet app requesting
  signatures. Identified by its **peer domain** — the host of its callback URL.
- **Relay**: the Cryptograph iPhone app. Receives requests at
  `https://cryptograph.watch/…`, enforces pairing state, forwards approved
  work to the signer, and delivers responses to the integrator callback.
- **Signer**: the Cryptograph Watch app. Renders every request on its own
  display from the same bytes it signs, and holds the approval surface.
- **Pairing**: the durable relationship between one integrator installation and
  one Cryptograph installation: pinned keys, grants, counters.

Requirement words (MUST, MUST NOT, SHOULD, MAY) follow RFC 2119.

## 2. Transport

### 2.1 Universal Links only

Every protocol message is an `https` URL opened app-to-app:

- Requests open `https://cryptograph.watch/<endpoint>`.
- Responses open the integrator's **callback URL**, which MUST be an `https`
  URL on a domain the integrator controls and has associated with its app via
  AASA.

Both sides MUST register the relevant paths in their
`apple-app-site-association` file and hold the `associated-domains`
entitlement. Domain control is the identity primitive of this protocol: iOS
will only deliver `https://cryptograph.watch/sign` to the genuine Cryptograph
app, and only deliver the callback to the app associated with the callback
domain.

### 2.2 Custom URL schemes are detection-only

The `cryptograph://` scheme exists solely so integrators can probe
installation with `canOpenURL(cryptograph://)` (declare `cryptograph` in
`LSApplicationQueriesSchemes`). The relay MUST reject any protocol message
that arrives over a custom scheme with no callback issued. Custom schemes are
claimable by any app and carry no domain proof; they MUST NOT carry signer
messages in either direction.

### 2.3 Endpoints

| URL | Message type(s) |
|---|---|
| `https://cryptograph.watch/pair` | `pair_request` |
| `https://cryptograph.watch/accounts` | `accounts_request` |
| `https://cryptograph.watch/sign` | `sign_request` |
| `https://cryptograph.watch/revoke` | `revoke` |
| `https://cryptograph.watch/rotate` | `rotate_key` |
| integrator callback URL | `pair_response`, `accounts_response`, `sign_response`, `revoke`, `rotate_key` |

All response types are delivered to the single callback URL fixed at pairing
time. Integrators dispatch on the envelope `type` field, not the path.

### 2.4 URL encoding and size limits

Each message URL carries exactly two query parameters:

- `req` (requests) or `res` (responses): base64url, no padding, of the UTF-8
  JSON **envelope** (§5).
- `sig`: base64url, no padding, of the sender's signature (§6).

Senders MUST keep the total URL length at or below **65,536 bytes** and the
serialized envelope at or below **49,152 bytes**. A relay receiving an
oversized request responds `payload_too_large`. Realistic
`eth_signTypedData_v4` payloads (tested against mainnet Permit2, Seaport, and
Blur orders) fit comfortably; §15 discusses the contingency plan if a future
integrator exceeds this.

### 2.5 Browser fallback

If the counterpart app is not installed (or AASA association fails), iOS opens
the URL in Safari and the envelope reaches a web server. The protocol treats
every URL as potentially logged by infrastructure:

- Nothing confidential ever appears outside an HPKE-sealed `body`.
- `cryptograph.watch/pair` and `/sign` serve an instructional web page
  ("install Cryptograph") and discard parameters.
- Integrator callback pages SHOULD do the equivalent.

A leaked envelope is replayable only until its `exp` and only once per
counter, and its body is unreadable without the recipient's private KEM key.

## 3. Cryptographic suite

Version 1 defines a single suite, **CSP1**:

| Function | Primitive |
|---|---|
| Message signatures | ECDSA over NIST P-256, SHA-256 digest, raw 64-byte `r‖s` |
| Body encryption | HPKE base mode (RFC 9180): DHKEM(P-256, HKDF-SHA256) = 0x0010, HKDF-SHA256 = 0x0001, AES-256-GCM = 0x0002 |
| Hashing | SHA-256 |
| Canonicalization | JCS (RFC 8785), restricted profile (§4.3) |

Each side holds two long-term P-256 key pairs per pairing:

- a **signature key** (`*_sig_pub`) used to sign envelopes, and
- a **KEM key** (`*_kem_pub`) that the other side encrypts bodies to.

Keys MUST be unique per pairing (fresh keys for each pairing) so that pairings
are unlinkable across integrators and revocation is surgical. Private keys
MUST be stored with device-only protection (on iOS:
`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, never synchronized).
Cryptograph's chain keys are unrelated to these keys and never leave the watch;
CSP keys are transport identity keys only.

## 4. Encodings

### 4.1 Binary values

All binary values are base64url without padding (RFC 4648 §5).

- Public keys: SEC1 compressed points, 33 bytes.
- Signatures: raw 64-byte `r‖s`.
- Nonces: 32 random bytes.
- HPKE output: `enc ‖ ct` concatenated, where `enc` is the 65-byte
  uncompressed encapsulated key defined by DHKEM(P-256).

### 4.2 Domain and address forms

- Domains are lowercase ASCII (IDNA A-labels). Displaying software MUST render
  the A-label form (`xn--…`) for any non-ASCII domain rather than the Unicode
  form, to defeat homograph spoofing.
- EVM accounts are EIP-55 checksummed addresses. Mixed-case addresses MUST
  carry a valid EIP-55 checksum; all-lowercase forms are accepted (they carry
  no checksum to verify).
- Chains are CAIP-2 identifiers restricted to the `eip155` namespace in v1,
  e.g. `eip155:1`.

### 4.3 Canonical JSON (JCS profile)

Signatures cover the JCS (RFC 8785) serialization of the envelope. CSP1
additionally restricts all protocol JSON (envelopes and sealed bodies) so that
every conforming JSON serializer can produce the canonical form:

- All numbers MUST be integers with magnitude ≤ 2^53 − 1. Envelope-level
  fields (`v`, `ctr`, `iat`, `exp`) MUST additionally be non-negative.
  (Sealed bodies may carry negative integers — EIP-712 messages legitimately
  contain them.)
- Strings MUST be valid UTF-8; no lone surrogates.
- No `null` values: absent means absent.

Under these restrictions JCS reduces to: UTF-8, object keys sorted by code
point, no insignificant whitespace, integers serialized without exponent,
sign, or leading zeros.

## 5. Envelope

Every message is one JSON object (the *envelope*):

```json
{
  "v": 1,
  "type": "sign_request",
  "pairing_id": "6BE2A38E-…",
  "ctr": 17,
  "iat": 1782300000,
  "exp": 1782300300,
  "body": "<base64url(enc ‖ ct)>"
}
```

Common fields:

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `v` | int | always | Protocol version. This document defines `1`. |
| `type` | string | always | Message type (§2.3 table). |
| `pairing_id` | string | all except `pair_request` | UUID assigned by the relay at pairing. |
| `ctr` | int | all except `pair_request`/`pair_response` | Sender's strictly-increasing counter (§10). |
| `iat` | int | always | Issued-at, Unix seconds. |
| `exp` | int | requests | Expiry, Unix seconds. `exp − iat` MUST be ≤ 600 for `sign_request`; receivers allow ±120 s clock skew on `iat`. |
| `body` | string | type-dependent | HPKE-sealed content (§7–§9). |

Unknown fields MUST be rejected (`invalid_request`) — the envelope is part of
the signed surface and silent extensions invite cross-version confusion.

### 5.1 Body sealing

`body` is produced by single-shot HPKE base-mode seal to the recipient's KEM
public key with:

- `info` = UTF-8 `"CSP1 body"`
- `aad` = UTF-8 `"CSP1|" + type + "|" + pairing_id + "|" + ctr`
  (for `pair_response`, which precedes counters, `ctr` is the literal `0`).

The AAD binds the ciphertext to its envelope position so a sealed body cannot
be transplanted between messages, even by a sender whose signature key is
compromised later.

## 6. Message authentication

Every message is signed by the sender's pairing signature key. The signature
input is the UTF-8 encoding of:

```
"CSP1" ‖ "|" ‖ type ‖ "|" ‖ destination_host ‖ "|" ‖ JCS(envelope)
```

where `destination_host` is the lowercase host of the URL the sender opens
(`cryptograph.watch` for requests; the callback host for responses), and
`JCS(envelope)` is the canonical serialization of the complete envelope. The
ECDSA-P256/SHA-256 signature travels in the `sig` query parameter.

Binding the destination host means a message captured in transit to one domain
cannot be replayed to a different domain.

Receivers MUST validate in this order and stop at the first failure:

1. Transport: message arrived on an allowed Universal-Link path (never a
   custom scheme).
2. Envelope parses, `v` supported, `type` known for this endpoint, no unknown
   fields.
3. Pairing exists and is not revoked (`unknown_pairing` / `revoked`);
   for `pair_request`, pairing must *not* already exist for an identical
   (`peer domain`, `peer_sig_pub`) — re-pairing requires user consent again.
4. Signature verifies against the pinned peer signature key (`pair_request`:
   against the key inside the envelope, §7.1).
5. `ctr` strictly greater than the stored high-water mark
   (`counter_replayed`).
6. `iat`/`exp` window valid (`expired`).
7. Body unseals with correct AAD (`decode_failed`).
8. Content rules for the type: grants, methods, checksums (§8–§9).

Only after step 5 succeeds is the counter high-water mark advanced; steps 6–8
failing still consume the counter (a signed, replay-protected message was
seen).

If validation fails at or before step 4, the relay MUST NOT open the callback
at all — an unauthenticated caller must not be able to use Cryptograph as a
URL-opening oracle. Failures at step 5 onward produce a signed error response
(§9.4).

## 7. Pairing

### 7.1 `pair_request` (integrator → relay)

The integrator generates fresh signature and KEM key pairs and a nonce, then
opens:

```
https://cryptograph.watch/pair?req=<b64url(envelope)>&sig=<b64url(signature)>
```

```json
{
  "v": 1,
  "type": "pair_request",
  "cb": "https://links.rabby.io/cryptograph-callback",
  "peer_sig_pub": "<b64url 33B>",
  "peer_kem_pub": "<b64url 33B>",
  "nonce_peer": "<b64url 32B>",
  "app_name": "Rabby",
  "iat": 1782300000,
  "exp": 1782300600
}
```

- `cb`: the callback URL. MUST be `https`, MUST NOT contain query or fragment,
  MUST NOT be an IP literal or `localhost`, and MUST NOT be the relay host
  itself (`cryptograph.watch`) — its endpoints belong to the relay. Subdomains
  of the relay host are permitted: only the relay operator can associate apps
  with them, so they serve first-party demo/test integrators (e.g.
  `demo.cryptograph.watch`). The callback host is the **peer domain** and the
  identity shown to the user everywhere.
- `app_name`: display-only hint, always rendered *subordinate to* the peer
  domain and never in place of it.
- The envelope is signed by `peer_sig_pub` itself: a proof of possession, not
  yet a proof of identity. Identity is established by delivering the response
  to `cb`, which only the app associated with that domain can receive.

`pair_request` has no `body`; there is nothing confidential yet and no
recipient key to seal to.

### 7.2 User consent

The relay MUST display the peer domain and collect explicit account/chain
grants:

> Allow **links.rabby.io** to request signatures from these accounts?

The user selects which EVM accounts and chains the pairing may reference. The
pairing is then confirmed **on the watch** — domain plus granted accounts on
the watch's own display — before any callback is issued. A pairing that the
watch has not confirmed does not exist.

### 7.3 `pair_response` (relay → integrator)

```json
{
  "v": 1,
  "type": "pair_response",
  "pairing_id": "6BE2A38E-…",
  "cg_sig_pub": "<b64url 33B>",
  "cg_kem_pub": "<b64url 33B>",
  "nonce_peer": "<echoed>",
  "nonce_cg": "<b64url 32B>",
  "req_hash": "<b64url 32B SHA-256 of JCS(pair_request envelope)>",
  "iat": 1782300042,
  "body": "<sealed grants>"
}
```

Sealed body:

```json
{
  "grants": [
    { "account": "0xAb58…c9E7", "chains": ["eip155:1", "eip155:42161"] }
  ],
  "methods": ["eth_signTransaction", "personal_sign", "eth_signTypedData_v4"],
  "limits": { "max_envelope_bytes": 49152, "max_pending_sign": 1 }
}
```

`req_hash` closes the transcript: the integrator MUST recompute the hash of
the exact `pair_request` envelope it sent and compare. Together with the
echoed `nonce_peer` and the domain-bound delivery of both legs, this yields
mutual authentication in two messages. On success the integrator pins
`cg_sig_pub`/`cg_kem_pub` and stores the pairing.

If the user declines, the relay opens the callback with a `pair_response`
envelope containing only `nonce_peer`, `req_hash`, `cg_sig_pub`, and
`error: "rejected_by_user"` — no `pairing_id`, no KEM key, no body. Like
`pair_request`, its signature is a self-signed proof of possession by the
included key; the integrator's assurance that the decline is genuine comes
from the domain-bound delivery, not the (unpinned) key.

### 7.4 Activation

A pairing is **provisional** on the relay until the first correctly signed
integrator message referencing it (usually the first `accounts_request` or
`sign_request`), which proves the integrator received the `pair_response` and
completed its side. Provisional pairings expire after 10 minutes and MUST NOT
be shown as connected wallets. This replaces a third pairing leg — one fewer
app switch with the same transcript guarantee, since the first request is
signed with the pinned peer key over material derived from the response.

## 8. Accounts

`accounts_request` (integrator → relay) has no body. The relay MUST require
user presence (app foregrounded by the Universal Link is sufficient; no
approval sheet is required) and responds with `accounts_response` whose sealed
body is identical in shape to the `pair_response` body — the *current* grants,
which may have narrowed since pairing. Integrators SHOULD call this on wallet
unlock to reconcile revoked or added grants.

## 9. Signing

### 9.1 `sign_request` (integrator → relay)

Sealed body:

```json
{
  "request_id": "0E1FA0C4-…",
  "account": "0xAb58…c9E7",
  "chain": "eip155:1",
  "method": "eth_signTransaction",
  "payload": { … }
}
```

`request_id` is a fresh UUID chosen by the integrator; the matching response
echoes it.

### 9.2 Methods and payloads

v1 supports exactly three methods:

**`eth_signTransaction`** — `payload` is a transaction object with 0x-hex
string members: required `to` (or absent for contract creation), `value`,
`data`, `nonce`, `chainId`, `gas`; either `gasPrice` or
`maxFeePerGas` + `maxPriorityFeePerGas`. The integrator is responsible for
nonce and fee selection (it owns the RPC relationship). The result is the
RLP-encoded signed raw transaction; **Cryptograph never broadcasts**. The
`chainId` inside the payload MUST match the envelope-level `chain` or the
relay rejects (`invalid_request`). Requests arriving with method name
`eth_sendTransaction` are treated as `eth_signTransaction` — same semantics,
signed bytes returned to the integrator to broadcast.

**`personal_sign`** — `payload` is `{ "message": "0x…" }`, the raw bytes to
sign under the EIP-191 personal-message prefix. The watch displays the UTF-8
decoding when the bytes are valid UTF-8, otherwise hex, and marks
non-UTF-8 messages as opaque.

**`eth_signTypedData_v4`** — `payload` is `{ "typedData": { … } }`, the parsed
EIP-712 object (not a doubly-encoded string). The relay recomputes the EIP-712
domain and message hashes; the watch renders the decoded structure through the
same display guards as WalletConnect typed-data requests today.

`eth_sign` is **not supported** (`unsupported_method`). It signs arbitrary
32-byte digests with no displayable structure, which cannot satisfy the
watch's display-what-you-sign invariant.

### 9.3 Relay and signer obligations

The relay MUST verify the `account`/`chain` pair is granted
(`grant_violation`) and the method is in the pairing's capability list, then
construct the signing intent from the *decrypted payload bytes* — the same
bytes are hashed into the intent's commitment, shipped to the watch, decoded
**on the watch**, displayed, and signed. The watch approval surface MUST show
the peer domain prominently:

> **links.rabby.io** requests signature

together with all consequential transaction details. If any detail cannot be
decoded and displayed, the watch fails closed and the relay responds
`decode_failed`.

At most `max_pending_sign` requests (v1: one) may be in flight per pairing;
further requests are refused with `busy`.

### 9.4 `sign_response` (relay → integrator)

Sealed body, success:

```json
{ "request_id": "0E1FA0C4-…", "result": { "signedTransaction": "0x02f8…" } }
```

`personal_sign` and `eth_signTypedData_v4` return
`{ "signature": "0x…" }` (65-byte `r‖s‖v`).

Failure:

```json
{ "request_id": "0E1FA0C4-…", "error": { "code": "rejected_by_user", "message": "Declined on watch" } }
```

### 9.5 Error codes

`invalid_request`, `unsupported_version`, `unknown_pairing`, `revoked`,
`invalid_signature`, `counter_replayed`, `expired`, `grant_violation`,
`unsupported_method`, `payload_too_large`, `decode_failed`,
`rejected_by_user`, `timeout`, `busy`, `rate_limited`, `internal_error`.

Errors at or below signature validation produce no callback (§6). All others
are signed, sealed responses. `timeout` is issued when the watch approval
window (the envelope `exp`) lapses.

## 10. Counters and replay protection

Each direction of each pairing has an independent counter starting at 1 with
the first post-pairing message. Senders increment monotonically; receivers
store the highest verified value and reject `ctr ≤ high-water`
(`counter_replayed`). Counters need not be contiguous — senders MAY burn
values (e.g. crashed before opening the URL). Both sides MUST persist
counters atomically with the pairing record; losing counter state invalidates
the pairing (fail closed, re-pair).

## 11. Revocation and rotation

- **Local revocation.** Either side can unilaterally mark a pairing revoked.
  Cryptograph exposes this in Settings → Connected wallets; all subsequent
  messages get `revoked`.
- **`revoke` message.** A signed envelope (no body) that tells the other side
  to mark the pairing revoked. Best-effort: local revocation is already final;
  the message is a courtesy that keeps both UIs truthful.
- **`rotate_key`.** Sealed body
  `{ "new_sig_pub": …, "new_kem_pub": …, "proof": … }` where either key may be
  present and `proof` is a signature by the **new** signature key over
  `"CSP1 rotate" ‖ pairing_id ‖ ctr ‖ new_sig_pub ‖ new_kem_pub` (b64url
  values concatenated with `|`). The envelope itself is signed by the current
  (old) key. Receivers pin the new key(s) only after both checks pass.
  Rotation does not change grants or counters.

## 12. Grants and capabilities

Grants are fixed at pairing and only ever *narrowed* without a new pairing
ceremony: the user may revoke an account or chain from Cryptograph settings at
any time (reflected in the next `accounts_response`), but adding accounts,
chains, or methods requires a fresh `pair_request` and watch confirmation.
There are no session keys, no automatic approvals, and no background signing
in v1; every `sign_request` requires an explicit watch approval.

## 13. Rate limiting

The relay SHOULD throttle per pairing (v1 implementation: 10 requests/min,
one pending sign) and MUST throttle `pair_request` presentation globally (one
consent sheet at a time; concurrent pair requests are dropped, not queued, to
keep consent deliberate). Requests beyond the rate limit are dropped without
a callback — every callback is an app switch, so answering a flood would
amplify it. The `rate_limited` code is reserved for transports where a
response is cheap.

## 14. Threat model

Assets: chain keys (on watch), signature authorization integrity, pairing
keys, user's account list. Adversaries considered:

**Malicious app on the same phone.** Can open `cryptograph.watch` URLs freely.
Cannot receive callbacks for a domain it doesn't own (AASA), so it cannot
complete a pairing under a foreign identity; a pairing it *does* complete is
labeled with its own domain everywhere, including on the watch at every
signing approval. Cannot read sealed bodies of other pairings. Can attempt
consent fatigue — mitigated by §13 and by pairing requiring watch
confirmation.

**Network / infrastructure observer.** Sees URLs only if a leg falls back to
Safari (§2.5). Learns envelope metadata (type, pairing id, counter), never
body content. Cannot forge (signatures), replay (counters + destination-host
binding + expiry), or redirect (host binding) messages.

**Compromised integrator (key theft).** Can request signatures within existing
grants — every one still requires watch display + approval, which is the
security floor of the whole design. Cannot widen grants without a new watch
ceremony. Recovery: revoke the pairing.

**Compromised relay (Cryptograph iPhone app).** Cannot forge chain signatures
(keys on watch) and cannot bypass on-watch display of the signed bytes
(commitment-hash binding, watch-side decode). It *can* misattribute the peer
domain shown on the watch, censor requests, and leak request metadata. Domain
attribution on the watch is therefore phone-attested; payload display is
watch-verified. This matches the existing WalletConnect trust posture and is
the deliberate residual risk of v1.

**Phishing domains.** Identity is the callback domain string; a user can still
be socially engineered to pair with `rabby-wallet.example`. Mitigations:
A-label rendering (§4.2), the phone's existing phishing-domain list applied at
pair time, domain shown at *every* signing approval, `app_name` never
substituting for the domain.

**What v1 does not defend against:** a jailbroken/compromised iOS (Universal
Link routing integrity assumed), a malicious integrator socially engineering
approval of transactions the user genuinely sees and approves (transaction
*content* warnings are the watch decoder's job and shared with all signing
paths), and traffic analysis of app switches.

## 15. Known limits and forward plan

- **URL capacity.** If a real integrator exceeds §2.4 limits, v2 will keep the
  Universal Link as the authenticated control channel carrying a SHA-256
  commitment plus an out-of-band sealed blob transfer. Not in v1: no current
  Rabby flow exceeded 20% of budget in testing.
- **EVM only.** `chain` is restricted to `eip155:*`. The envelope, pairing,
  and grant machinery are chain-agnostic by construction; additional
  namespaces are a v2 concern gated on the watch having display-grade decoding
  for them.
- **iOS only.** Android (App Links + the Android watch app) is tracked
  separately.

## 16. Versioning

`v` is an integer. Receivers reject unknown versions with
`unsupported_version` (signed response where a pairing exists, silent drop
otherwise). Suite agility is deliberately absent: a future suite is a new
protocol version, not a negotiation.

## 17. Test vectors

Machine-readable vectors live in
`AppCore/Tests/AppCoreTests/Fixtures/SignerProtocol/` and are mirrored in the
TypeScript SDK (`sdk/signer-protocol/test/vectors/`); both test suites consume
byte-identical files:

- `jcs_vectors.json` — envelope → canonical bytes.
- `signing_input_vectors.json` — envelope + destination host → signature
  input bytes, plus fixed-key signatures that MUST verify.
- `hpke_vectors.json` — fixed recipient key, fixed ephemeral seed →
  `enc ‖ ct` (generated by the TypeScript implementation, opened by CryptoKit;
  CryptoKit cannot fix ephemeral keys, so Swift-side sealing is covered by
  round-trip tests).
- `pairing_transcript.json` — a full pair/sign/response transcript with all
  intermediate values.

ECDSA signatures are randomized; vectors therefore test *verification* against
recorded signatures and byte-exactness of signing inputs, not signature
reproduction.
