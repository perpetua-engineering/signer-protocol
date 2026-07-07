# Cryptograph Signer Protocol — React Native shell

Bare-bones harness validating that `@perpetua/signer-protocol` (pure JS,
noble-based — no native crypto modules) drives the full Universal-Link round
trip from React Native, i.e. the exact transport pattern a Rabby Mobile
`eth-keyring-cryptograph` keyring would use:

- `Linking.openURL('https://cryptograph.watch/pair?req=…&sig=…')`
- callback handled via `Linking.addEventListener('url', …)`

This directory intentionally contains only `App.tsx` and `package.json` — it
is source to drop into a bare RN app, not a committed RN project (no ios/
android trees, no lockfile).

## Setup

```bash
npx @react-native-community/cli init SignerShell --version 0.76.5
cp App.tsx package.json SignerShell/   # merge deps, then: cd SignerShell && npm install
```

Then, in the generated iOS project:

1. Set a bundle id your team can provision.
2. Add the `Associated Domains` capability with `applinks:<your-domain>` for
   a domain you control, serve an AASA associating your callback path, and
   set `CALLBACK_URL` in `App.tsx` accordingly.
3. Add `cryptograph` to `LSApplicationQueriesSchemes` in Info.plist if you
   want to probe for the Cryptograph app with `Linking.canOpenURL`.
4. Run on a physical device paired with the Cryptograph watch app.

A real integration must persist `pending` / `pairing` (Keychain or
MMKV/AsyncStorage) **before** opening each request URL — counters must never
be reused. See the SDK README and the protocol spec
(<https://cryptograph.watch/signer-protocol>) §10.
