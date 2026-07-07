//
// Minimal React Native shell for the Cryptograph Signer Protocol (CR-1277).
//
// Purpose: validate the exact transport pattern a Rabby Mobile
// eth-keyring-cryptograph keyring would use — Linking.openURL toward
// https://cryptograph.watch/* and a Universal-Link callback handled via
// Linking's 'url' event — with all protocol logic in
// @perpetua/signer-protocol (pure JS, no native crypto modules needed).
//
// This is a harness, not a wallet: state lives in AsyncStorage-free React
// state plus a module-level cache, and the callback domain must be one your
// Apple Developer team can associate with the app (see README).
//

import React, { useCallback, useEffect, useState } from 'react';
import {
  Button,
  Linking,
  SafeAreaView,
  ScrollView,
  StyleSheet,
  Text,
  View,
} from 'react-native';
import {
  createPairRequest,
  createSignRequest,
  handleCallback,
  handlePairCallback,
  type Pairing,
  type PendingPair,
} from '@perpetua/signer-protocol';

// Configure to a domain your team owns + associated with this app via AASA.
const CALLBACK_URL = 'https://example.invalid/cryptograph-callback';

export default function App(): React.JSX.Element {
  const [pending, setPending] = useState<PendingPair | null>(null);
  const [pairing, setPairing] = useState<Pairing | null>(null);
  const [log, setLog] = useState<string[]>([]);

  const append = useCallback((line: string) => {
    setLog((previous) => [line, ...previous].slice(0, 100));
  }, []);

  const onIncomingUrl = useCallback(
    (url: string) => {
      append(`← ${url.slice(0, 80)}…`);
      try {
        if (pending) {
          const event = handlePairCallback(url, pending);
          setPending(null);
          if (event.kind === 'paired') {
            setPairing(event.pairing);
            append(`paired: ${event.pairing.grants.grants[0]?.account}`);
          } else {
            append('pairing declined');
          }
          return;
        }
        if (pairing) {
          const event = handleCallback(url, pairing);
          setPairing(event.pairing);
          if (event.kind === 'sign') {
            append(`sign result: ${JSON.stringify(event.result).slice(0, 120)}`);
          } else {
            append(`event: ${event.kind}`);
          }
        }
      } catch (error) {
        append(`callback rejected: ${String(error)}`);
      }
    },
    [append, pending, pairing],
  );

  useEffect(() => {
    const subscription = Linking.addEventListener('url', ({ url }) => onIncomingUrl(url));
    Linking.getInitialURL().then((url) => url && onIncomingUrl(url));
    return () => subscription.remove();
  }, [onIncomingUrl]);

  const pair = async () => {
    const { url, pending: next } = createPairRequest(CALLBACK_URL, 'RNShell');
    setPending(next); // persist BEFORE opening in a real wallet
    append(`→ pair_request (${url.length} chars)`);
    await Linking.openURL(url);
  };

  const signMessage = async () => {
    if (!pairing) return;
    const grant = pairing.grants.grants[0];
    if (!grant) return;
    const { url, pairing: next } = createSignRequest(pairing, {
      requestId: `${Date.now()}-rnshell`,
      account: grant.account,
      chain: grant.chains[0] ?? 'eip155:1',
      method: 'personal_sign',
      payload: { message: '0x48656c6c6f2066726f6d20524e5368656c6c' },
    });
    setPairing(next); // counters advance before the URL opens
    append(`→ sign_request (${url.length} chars)`);
    await Linking.openURL(url);
  };

  return (
    <SafeAreaView style={styles.container}>
      <Text style={styles.title}>Cryptograph Signer — RN shell</Text>
      <View style={styles.buttons}>
        <Button title="Pair with Cryptograph" onPress={pair} />
        <Button title="Sign message" onPress={signMessage} disabled={!pairing} />
      </View>
      <ScrollView style={styles.log}>
        {log.map((line, index) => (
          <Text key={index} style={styles.logLine}>
            {line}
          </Text>
        ))}
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, padding: 16 },
  title: { fontSize: 18, fontWeight: '600', marginBottom: 12 },
  buttons: { gap: 8, marginBottom: 12 },
  log: { flex: 1 },
  logLine: { fontFamily: 'Menlo', fontSize: 11, marginBottom: 4 },
});
