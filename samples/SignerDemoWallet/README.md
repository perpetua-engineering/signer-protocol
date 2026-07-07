# SignerDemoWallet

A minimal third-party wallet that exercises the **Cryptograph Signer
Protocol** (CR-1277) end to end from the integrator side: pair with the
Cryptograph iPhone app over a Universal Link, receive the domain-bound
callback, and request EVM signatures that the user approves on their Apple
Watch — including a deliberately large Permit2 typed-data batch that
validates real-device URL capacity (spec §2.4).

Spec: [docs/SIGNER_PROTOCOL.md](../../docs/SIGNER_PROTOCOL.md) ·
published at <https://cryptograph.watch/signer-protocol>

## How it works

The app compiles the integrator-side protocol sources straight from
`Shared/SignerProtocol` (`CSPIntegratorSession` is the reference client), so
the sample always tracks the in-repo implementation. TypeScript integrators
use `@perpetua/signer-protocol` (`sdk/signer-protocol`), which is
byte-compatible — the two implementations share cross-implementation test
vectors.

- Callback URL: `https://demo.cryptograph.watch/signer-demo-callback`
- Bundle id: `watch.perpetua.signerdemo`
- The combined AASA (`website/.well-known/apple-app-site-association`, served
  on every host including demo.cryptograph.watch) associates that path with
  this bundle id; the app's `applinks:demo.cryptograph.watch` entitlement
  scopes the association to the subdomain.

## Build

```bash
ruby generate_project.rb        # regenerates SignerDemoWallet.xcodeproj
open SignerDemoWallet.xcodeproj
```

Run on a **physical device** (paired with the Cryptograph watch app) for the
full Universal-Link round trip — simulators do not reliably route
app-to-app Universal Links. Both apps must be installed from builds whose
provisioning includes the `associated-domains` entitlement, and both AASA
files must be deployed (`deploy-website`).

## What to test

1. **Pair with Cryptograph** — Cryptograph shows the consent sheet with
   `demo.cryptograph.watch` as the requesting domain; the pairing must then be
   confirmed on the watch.
2. **Sign personal message / transaction / typed data** — each opens
   Cryptograph, which forwards to the watch; the watch approval surface must
   show `demo.cryptograph.watch requests signature` prominently.
3. **URL budget** — the typed-data button sends a 20-token Permit2 batch;
   the protocol log prints the request URL size in bytes.
4. **Revocation** — disconnect from Cryptograph's Connected Wallets settings;
   the demo receives the `revoke` message on its next foreground.
