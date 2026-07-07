//
//  CSPPairingStore.swift
//  Cryptograph
//
//  Relay-side persistence for Signer Protocol pairings. The whole pairing
//  table (records, pinned peer keys, local private keys, counters) is one
//  keychain item so counter updates persist atomically with the record
//  (docs/SIGNER_PROTOCOL.md §10). Device-only accessibility, never synced.
//

import Foundation

public protocol CSPPairingPersistence {
    func loadAll() -> [CSPPairingRecord]
    func saveAll(_ records: [CSPPairingRecord]) -> Bool
}

/// Keychain-backed production persistence.
public final class CSPKeychainPairingPersistence: CSPPairingPersistence {
    private let store: KeychainStore<[CSPPairingRecord]>

    public init() {
        store = KeychainStore<[CSPPairingRecord]>(
            service: "watch.perpetua.cryptograph.signerlink",
            account: "pairings.v1",
            logPrefix: "CSPPairingStore"
        )
    }

    public func loadAll() -> [CSPPairingRecord] { store.load() ?? [] }

    @discardableResult
    public func saveAll(_ records: [CSPPairingRecord]) -> Bool { store.save(records) }
}

/// In-memory persistence for tests and previews.
public final class CSPInMemoryPairingPersistence: CSPPairingPersistence {
    private var records: [CSPPairingRecord] = []

    public init() {}

    public func loadAll() -> [CSPPairingRecord] { records }

    public func saveAll(_ records: [CSPPairingRecord]) -> Bool {
        self.records = records
        return true
    }
}

/// Serialized access to the pairing table.
@MainActor
public final class CSPPairingStore: ObservableObject {
    public static let shared = CSPPairingStore(persistence: CSPKeychainPairingPersistence())

    @Published public private(set) var pairings: [CSPPairingRecord] = []

    private let persistence: CSPPairingPersistence

    public init(persistence: CSPPairingPersistence) {
        self.persistence = persistence
        pairings = persistence.loadAll()
        pruneExpiredProvisional()
    }

    public func pairing(id: String) -> CSPPairingRecord? {
        pairings.first { $0.id == id }
    }

    /// Live (non-revoked, non-expired-provisional) pairings for UI.
    public var livePairings: [CSPPairingRecord] {
        pairings.filter { $0.status != .revoked && !$0.isExpiredProvisional }
    }

    /// Inserts or replaces by id and persists. Returns false if the keychain
    /// write failed — callers MUST treat that as fatal for the operation
    /// (fail closed; never proceed with an unpersisted counter).
    @discardableResult
    public func upsert(_ record: CSPPairingRecord) -> Bool {
        var updated = pairings.filter { $0.id != record.id }
        updated.append(record)
        guard persistence.saveAll(updated) else {
            CXLog("CSPPairingStore: persist failed for pairing \(record.id)")
            return false
        }
        pairings = updated
        return true
    }

    /// Marks a pairing revoked (local revocation, §11) and persists.
    @discardableResult
    public func revoke(id: String) -> Bool {
        guard var record = pairing(id: id) else { return false }
        record.status = .revoked
        return upsert(record)
    }

    /// Removes revoked records from storage (Settings "remove" action).
    @discardableResult
    public func delete(id: String) -> Bool {
        let updated = pairings.filter { $0.id != id }
        guard persistence.saveAll(updated) else { return false }
        pairings = updated
        return true
    }

    private func pruneExpiredProvisional() {
        let pruned = pairings.filter { !$0.isExpiredProvisional }
        if pruned.count != pairings.count, persistence.saveAll(pruned) {
            pairings = pruned
        }
    }
}
