//
//  DemoWalletView.swift
//  SignerDemoWallet
//

import SwiftUI

struct DemoWalletView: View {
    @EnvironmentObject private var model: DemoWalletModel

    var body: some View {
        NavigationStack {
            List {
                Section("Pairing") {
                    if let account = model.grantedAccount {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Paired with Cryptograph")
                                .font(.headline)
                            Text(account)
                                .font(.system(.caption, design: .monospaced))
                                .truncationMode(.middle)
                                .lineLimit(1)
                            if let chain = model.grantedChain {
                                Text(chain).font(.caption2).foregroundColor(.secondary)
                            }
                        }
                        Button("Refresh granted accounts") { model.refreshAccounts() }
                        Button("Forget pairing", role: .destructive) { model.forget() }
                    } else {
                        Button {
                            model.pair()
                        } label: {
                            Label("Pair with Cryptograph", systemImage: "applewatch.radiowaves.left.and.right")
                        }
                        if model.pendingPair != nil {
                            Text("Waiting for the Cryptograph callback…")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                    }
                }

                if model.grantedAccount != nil {
                    Section {
                        Button("Sign personal message") { model.signPersonalMessage() }
                        Button("Sign transaction (0.01 ETH)") { model.signTransaction() }
                        Button("Sign typed data (large Permit2 batch)") { model.signTypedData() }
                    } header: {
                        Text("Request a signature")
                    } footer: {
                        Text("Each request opens Cryptograph; approval happens on the Apple Watch, which displays this app's verified domain.")
                    }
                }

                if let result = model.lastResult {
                    Section("Last result") {
                        Text(result)
                            .font(.system(.caption2, design: .monospaced))
                            .lineLimit(6)
                            .textSelection(.enabled)
                    }
                }

                Section("Protocol log") {
                    ForEach(model.log.reversed()) { line in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(line.text)
                                .font(.system(.caption, design: .monospaced))
                            Text(line.timestamp.formatted(date: .omitted, time: .standard))
                                .font(.caption2)
                                .foregroundColor(.secondary)
                        }
                    }
                }
            }
            .navigationTitle("SignerDemo")
        }
    }
}
