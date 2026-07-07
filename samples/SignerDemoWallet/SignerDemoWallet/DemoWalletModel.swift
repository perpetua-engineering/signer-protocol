//
//  DemoWalletModel.swift
//  SignerDemoWallet
//
//  Integrator-side state machine for the demo: drives CSPIntegratorSession
//  (the same reference implementation the protocol's unit tests exercise)
//  and persists pairing state across launches.
//

import Combine
import Foundation
import UIKit

@MainActor
final class DemoWalletModel: ObservableObject {
    /// Callback URL this demo owns. The AASA on demo.cryptograph.watch
    /// associates /signer-demo-callback with this app's bundle id.
    static let callbackURL = "https://demo.cryptograph.watch/signer-demo-callback"

    @Published private(set) var pairing: CSPIntegratorPairing?
    @Published private(set) var pendingPair: CSPIntegratorPendingPair?
    @Published private(set) var log: [LogLine] = []
    @Published private(set) var lastResult: String?

    struct LogLine: Identifiable {
        let id = UUID()
        let timestamp = Date()
        let text: String
    }

    private let pairingStore = CodableDefaults<CSPIntegratorPairing>(key: "demo.pairing")
    private let pendingStore = CodableDefaults<CSPIntegratorPendingPair>(key: "demo.pendingPair")

    init() {
        pairing = pairingStore.load()
        pendingPair = pendingStore.load()
    }

    var grantedAccount: String? {
        pairing?.grants.grants.first?.account
    }

    var grantedChain: String? {
        pairing?.grants.grants.first?.chains.first
    }

    // MARK: - Actions

    func pair() {
        do {
            let (url, pending) = try CSPIntegratorSession.makePairRequest(
                callbackURL: Self.callbackURL,
                appName: "SignerDemo"
            )
            pendingStore.save(pending)
            pendingPair = pending
            append("→ pair_request (\(url.absoluteString.utf8.count) URL bytes)")
            open(url)
        } catch {
            append("pair_request failed: \(error)")
        }
    }

    func refreshAccounts() {
        guard let pairing else { return }
        do {
            let (url, updated) = try CSPIntegratorSession.makeAccountsRequest(pairing: pairing)
            persist(updated)  // counters advance before the URL opens
            append("→ accounts_request ctr=\(updated.outboundCounter)")
            open(url)
        } catch {
            append("accounts_request failed: \(error)")
        }
    }

    func signPersonalMessage() {
        let message = Data("Hello from SignerDemo at \(Date().ISO8601Format())".utf8)
        sendSignRequest(
            method: "personal_sign",
            payload: .object(["message": .string("0x" + message.map { String(format: "%02x", $0) }.joined())])
        )
    }

    func signTransaction() {
        sendSignRequest(
            method: "eth_signTransaction",
            payload: .object([
                "to": .string("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"),
                "value": .string("0x2386f26fc10000"),  // 0.01 ETH
                "data": .string("0x"),
                "nonce": .string("0x0"),
                "chainId": .string("0x1"),
                "gas": .string("0x5208"),
                "maxFeePerGas": .string("0x59682f00"),
                "maxPriorityFeePerGas": .string("0x3b9aca00"),
            ])
        )
    }

    /// Sends a large realistic Permit2 batch — doubles as the ticket's
    /// URL-length validation with real typed data on a real device.
    func signTypedData() {
        var details: [CSPJSON] = []
        for index in 0..<20 {
            details.append(.object([
                "token": .string("0x" + String(repeating: String(format: "%02x", index + 1), count: 20)),
                "amount": .string("0xffffffffffffffffffffffffffffffff"),
                "expiration": .int(1_900_000_000),
                "nonce": .int(Int64(index)),
            ]))
        }
        let typedData = CSPJSON.object([
            "types": .object([
                "EIP712Domain": .array([
                    .object(["name": .string("name"), "type": .string("string")]),
                    .object(["name": .string("chainId"), "type": .string("uint256")]),
                    .object(["name": .string("verifyingContract"), "type": .string("address")]),
                ]),
                "PermitBatch": .array([
                    .object(["name": .string("details"), "type": .string("PermitDetails[]")]),
                    .object(["name": .string("spender"), "type": .string("address")]),
                    .object(["name": .string("sigDeadline"), "type": .string("uint256")]),
                ]),
                "PermitDetails": .array([
                    .object(["name": .string("token"), "type": .string("address")]),
                    .object(["name": .string("amount"), "type": .string("uint160")]),
                    .object(["name": .string("expiration"), "type": .string("uint48")]),
                    .object(["name": .string("nonce"), "type": .string("uint48")]),
                ]),
            ]),
            "domain": .object([
                "name": .string("Permit2"),
                "chainId": .int(1),
                "verifyingContract": .string("0x000000000022D473030F116dDEE9F6B43aC78BA3"),
            ]),
            "primaryType": .string("PermitBatch"),
            "message": .object([
                "details": .array(details),
                "spender": .string("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"),
                "sigDeadline": .int(1_900_000_000),
            ]),
        ])
        sendSignRequest(method: "eth_signTypedData_v4", payload: .object(["typedData": typedData]))
    }

    func forget() {
        pairingStore.delete()
        pendingStore.delete()
        pairing = nil
        pendingPair = nil
        lastResult = nil
        append("Pairing forgotten locally")
    }

    private func sendSignRequest(method: String, payload: CSPJSON) {
        guard let pairing, let account = grantedAccount, let chain = grantedChain else {
            append("Not paired")
            return
        }
        do {
            let body = CSPSignRequestBody(
                requestID: UUID().uuidString,
                account: account,
                chain: chain,
                method: method,
                payload: payload
            )
            let (url, updated) = try CSPIntegratorSession.makeSignRequest(pairing: pairing, body: body)
            persist(updated)
            append("→ sign_request \(method) ctr=\(updated.outboundCounter) (\(url.absoluteString.utf8.count) URL bytes)")
            open(url)
        } catch {
            append("sign_request failed: \(error)")
        }
    }

    // MARK: - Callback handling

    func handleCallback(_ url: URL) {
        append("← callback \(url.path)")

        if let pendingPair {
            if let event = try? CSPIntegratorSession.handlePairCallback(url: url, pending: pendingPair) {
                pendingStore.delete()
                self.pendingPair = nil
                switch event {
                case .paired(let newPairing):
                    persist(newPairing)
                    append("Paired! Accounts: \(newPairing.grants.grants.map(\.account).joined(separator: ", "))")
                case .pairDeclined:
                    append("Pairing declined in Cryptograph")
                default:
                    break
                }
                return
            }
        }

        guard let pairing else {
            append("Callback with no pairing — ignored")
            return
        }
        do {
            let event = try CSPIntegratorSession.handleCallback(url: url, pairing: pairing)
            switch event {
            case .accounts(let grants, let updated):
                persist(updated)
                append("Accounts refreshed: \(grants.grants.flatMap(\.chains).joined(separator: ", "))")
            case .signResult(let result, let updated):
                persist(updated)
                switch result {
                case .signedTransaction(_, let raw):
                    lastResult = raw
                    append("✓ signed transaction (\(raw.count) chars)")
                case .signature(_, let signature):
                    lastResult = signature
                    append("✓ signature \(signature.prefix(20))…")
                case .failure(_, let error):
                    lastResult = nil
                    append("✗ \(error.code.rawValue): \(error.message)")
                }
            case .revoked(let updated):
                persist(updated)
                pairingStore.delete()
                self.pairing = nil
                append("Pairing revoked by Cryptograph")
            case .keysRotated(let updated):
                persist(updated)
                append("Cryptograph rotated its keys")
            default:
                break
            }
        } catch {
            append("Callback rejected: \(error)")
        }
    }

    // MARK: - Helpers

    private func persist(_ pairing: CSPIntegratorPairing) {
        pairingStore.save(pairing)
        self.pairing = pairing
    }

    private func open(_ url: URL) {
        UIApplication.shared.open(url) { [weak self] success in
            if !success {
                Task { @MainActor in
                    self?.append("Open failed — is Cryptograph installed?")
                }
            }
        }
    }

    private func append(_ text: String) {
        log.append(LogLine(text: text))
        if log.count > 200 { log.removeFirst(log.count - 200) }
    }
}

/// Tiny Codable-in-UserDefaults store. A real wallet would use the Keychain;
/// the demo optimizes for inspectability.
struct CodableDefaults<Value: Codable> {
    let key: String

    func load() -> Value? {
        guard let data = UserDefaults.standard.data(forKey: key) else { return nil }
        return try? JSONDecoder().decode(Value.self, from: data)
    }

    func save(_ value: Value) {
        if let data = try? JSONEncoder().encode(value) {
            UserDefaults.standard.set(data, forKey: key)
        }
    }

    func delete() {
        UserDefaults.standard.removeObject(forKey: key)
    }
}
