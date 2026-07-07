# @perpetua/signer-protocol

TypeScript SDK for the **Cryptograph Signer Protocol** (CSP v1) — a
permissionless Universal-Link protocol that lets any iOS wallet request EVM
signatures approved on the user's Apple Watch. Keys never leave the watch;
your app keeps its UX and gains a hardware-wallet-class signer with no BLE,
no QR loops, and no relay server.

Spec: <https://cryptograph.watch/signer-protocol>

Pure JavaScript over [noble](https://paulmillr.com/noble/) primitives — no
WebCrypto, no native modules — so it runs unmodified in React Native,
browsers, and Node ≥ 18.

## Install

```bash
npm install @perpetua/signer-protocol
```

## Usage

Your app needs a Universal-Link **callback URL** on a domain you control
(AASA-associated with your app). That domain is the identity Cryptograph
shows the user — on the iPhone at pairing and on the watch at every
signature.

### Pair

```ts
import { createPairRequest, handlePairCallback } from '@perpetua/signer-protocol';

const { url, pending } = createPairRequest(
  'https://links.yourwallet.example/cryptograph-callback',
  'YourWallet',
);
await persistPending(pending);   // BEFORE opening
await Linking.openURL(url);      // opens the Cryptograph app

// later, in your Universal-Link handler:
const event = handlePairCallback(callbackUrl, pending);
if (event.kind === 'paired') await persistPairing(event.pairing);
```

### Sign

```ts
import { createSignRequest, handleCallback } from '@perpetua/signer-protocol';

const { url, pairing: next } = createSignRequest(pairing, {
  requestId: crypto.randomUUID(),
  account: pairing.grants.grants[0].account,
  chain: 'eip155:1',
  method: 'eth_signTransaction',   // or personal_sign / eth_signTypedData_v4
  payload: { to, value, data, nonce, chainId: '0x1', gas, maxFeePerGas, maxPriorityFeePerGas },
});
await persistPairing(next);        // counters advance BEFORE the URL opens
await Linking.openURL(url);

// in your Universal-Link handler:
const event = handleCallback(callbackUrl, next);
if (event.kind === 'sign') {
  await persistPairing(event.pairing);
  // event.result: { signedTransaction } | { signature } | { error }
}
```

`eth_signTransaction` returns the RLP-encoded signed raw transaction — your
wallet broadcasts it; Cryptograph never does.

### Two rules that matter

1. **Persist state before opening every URL.** Counters are the replay
   defense; a reused counter is a dropped request, and lost counter state
   invalidates the pairing (fail closed, re-pair).
2. **Verify every callback with `handleCallback`/`handlePairCallback`.**
   They check the pinned Cryptograph signature, the destination-host
   binding, the counter, and unseal the body — never parse callback
   parameters yourself.

## Detection

Declare `cryptograph` in `LSApplicationQueriesSchemes` and probe with
`Linking.canOpenURL('cryptograph://')`. The custom scheme is
detection-only — protocol messages travel exclusively over Universal Links.

## Testing

```bash
npm test                    # Jest: JCS, HPKE (incl. RFC 9180 A.3 vectors), protocol round trips
npm run generate-vectors    # regenerate cross-implementation fixtures (deterministic)
```

The fixtures in `test/vectors/` are verified byte-for-byte by the Swift
implementation inside the Cryptograph app — the two sides can never drift
silently.

## License

MIT © Perpetua Labs LLC
