//
//  CSPModels.swift
//  Cryptograph
//
//  Data model for the Cryptograph Signer Protocol v1: message types, error
//  codes, grants, and the pairing record. See docs/SIGNER_PROTOCOL.md.
//

import Foundation

// MARK: - Message types (§2.3)

public enum CSPMessageType: String, Codable, CaseIterable {
    case pairRequest = "pair_request"
    case pairResponse = "pair_response"
    case accountsRequest = "accounts_request"
    case accountsResponse = "accounts_response"
    case signRequest = "sign_request"
    case signResponse = "sign_response"
    case revoke = "revoke"
    case rotateKey = "rotate_key"

    /// Types the relay accepts, keyed by request path.
    public static func expectedType(forPath path: String) -> CSPMessageType? {
        switch path {
        case "/pair": return .pairRequest
        case "/accounts": return .accountsRequest
        case "/sign": return .signRequest
        case "/revoke": return .revoke
        case "/rotate": return .rotateKey
        default: return nil
        }
    }
}

// MARK: - Error codes (§9.5)

public enum CSPErrorCode: String, Codable, CaseIterable, Error {
    case invalidRequest = "invalid_request"
    case unsupportedVersion = "unsupported_version"
    case unknownPairing = "unknown_pairing"
    case revoked = "revoked"
    case invalidSignature = "invalid_signature"
    case counterReplayed = "counter_replayed"
    case expired = "expired"
    case grantViolation = "grant_violation"
    case unsupportedMethod = "unsupported_method"
    case payloadTooLarge = "payload_too_large"
    case decodeFailed = "decode_failed"
    case rejectedByUser = "rejected_by_user"
    case timeout = "timeout"
    case busy = "busy"
    case rateLimited = "rate_limited"
    case internalError = "internal_error"
}

public struct CSPError: Codable, Equatable, Error {
    public let code: CSPErrorCode
    public let message: String

    public init(code: CSPErrorCode, message: String) {
        self.code = code
        self.message = message
    }
}

// MARK: - Protocol constants (§2.4, §5, §13)

public enum CSPLimits {
    public static let maxURLBytes = 65_536
    public static let maxEnvelopeBytes = 49_152
    public static let maxSignRequestLifetimeSeconds: Int64 = 600
    public static let clockSkewSeconds: Int64 = 120
    public static let provisionalPairingLifetimeSeconds: TimeInterval = 600
    public static let maxPendingSignRequests = 1
    public static let maxRequestsPerMinute = 10
}

// MARK: - Grants (§12)

public struct CSPGrant: Codable, Equatable {
    /// EIP-55 checksummed account address.
    public let account: String
    /// CAIP-2 chain identifiers, `eip155` namespace only in v1.
    public let chains: [String]

    public init(account: String, chains: [String]) {
        self.account = account
        self.chains = chains
    }
}

public struct CSPGrantSet: Codable, Equatable {
    public let grants: [CSPGrant]
    /// Supported method names, e.g. `eth_signTransaction`.
    public let methods: [String]

    public static let v1Methods = [
        "eth_signTransaction",
        "personal_sign",
        "eth_signTypedData_v4",
    ]

    public init(grants: [CSPGrant], methods: [String] = CSPGrantSet.v1Methods) {
        self.grants = grants
        self.methods = methods
    }

    public func allows(account: String, chain: String) -> Bool {
        grants.contains { grant in
            grant.account.lowercased() == account.lowercased() && grant.chains.contains(chain)
        }
    }

    /// True when the set still grants anything at all.
    public var isEmpty: Bool {
        grants.allSatisfy { $0.chains.isEmpty }
    }
}

// MARK: - Pairing record (§7, §10)

public enum CSPPairingStatus: String, Codable {
    /// pair_response issued, first authenticated integrator message not yet
    /// seen. Expires after CSPLimits.provisionalPairingLifetimeSeconds.
    case provisional
    case active
    case revoked
}

/// One pairing between this Cryptograph installation and one integrator.
/// Counters persist atomically with the record: the whole pairing table is a
/// single keychain item (see CSPPairingStore).
public struct CSPPairingRecord: Codable, Equatable, Identifiable {
    public let id: String
    /// Host of the callback URL; the integrator's displayed identity.
    public let peerDomain: String
    /// Full callback URL (https, no query/fragment) fixed at pairing.
    public let callbackURL: String
    /// Display-only integrator name, always rendered subordinate to the domain.
    public let appName: String?
    /// Pinned integrator keys (SEC1 compressed, 33 bytes).
    public var peerSigningPublicKey: Data
    public var peerKEMPublicKey: Data
    /// Cryptograph's per-pairing key material.
    public var localKeys: CSPKeyPairSet
    public var grants: CSPGrantSet
    public var status: CSPPairingStatus
    /// Highest verified inbound counter (integrator → relay).
    public var inboundCounter: Int64
    /// Last used outbound counter (relay → integrator).
    public var outboundCounter: Int64
    public let createdAt: Date
    public var lastUsedAt: Date

    public init(
        id: String = UUID().uuidString,
        peerDomain: String,
        callbackURL: String,
        appName: String?,
        peerSigningPublicKey: Data,
        peerKEMPublicKey: Data,
        localKeys: CSPKeyPairSet = CSPKeyPairSet(),
        grants: CSPGrantSet,
        status: CSPPairingStatus = .provisional,
        inboundCounter: Int64 = 0,
        outboundCounter: Int64 = 0,
        createdAt: Date = Date(),
        lastUsedAt: Date = Date()
    ) {
        self.id = id
        self.peerDomain = peerDomain
        self.callbackURL = callbackURL
        self.appName = appName
        self.peerSigningPublicKey = peerSigningPublicKey
        self.peerKEMPublicKey = peerKEMPublicKey
        self.localKeys = localKeys
        self.grants = grants
        self.status = status
        self.inboundCounter = inboundCounter
        self.outboundCounter = outboundCounter
        self.createdAt = createdAt
        self.lastUsedAt = lastUsedAt
    }

    public var isExpiredProvisional: Bool {
        status == .provisional
            && Date().timeIntervalSince(createdAt) > CSPLimits.provisionalPairingLifetimeSeconds
    }
}

// MARK: - Sign request body (§9.1)

public struct CSPSignRequestBody: Equatable {
    public let requestID: String
    public let account: String
    public let chain: String
    public let method: String
    /// Method-specific payload subtree, still in the restricted JSON model.
    public let payload: CSPJSON

    public init(requestID: String, account: String, chain: String, method: String, payload: CSPJSON) {
        self.requestID = requestID
        self.account = account
        self.chain = chain
        self.method = method
        self.payload = payload
    }

    /// Methods the v1 relay will forward to the watch. `eth_sendTransaction`
    /// is accepted as an alias with identical sign-and-return semantics;
    /// Cryptograph never broadcasts.
    public var normalizedMethod: String? {
        switch method {
        case "eth_signTransaction", "eth_sendTransaction":
            return "eth_signTransaction"
        case "personal_sign", "eth_signTypedData_v4":
            return method
        default:
            return nil
        }
    }

    public func encode() throws -> Data {
        let object: [String: CSPJSON] = [
            "request_id": .string(requestID),
            "account": .string(account),
            "chain": .string(chain),
            "method": .string(method),
            "payload": payload,
        ]
        return CSPJSON.object(object).canonicalData()
    }

    public static func decode(_ data: Data) throws -> CSPSignRequestBody {
        let object = try CSPJSON.parseObject(data)
        guard let requestID = object["request_id"]?.stringValue,
              let account = object["account"]?.stringValue,
              let chain = object["chain"]?.stringValue,
              let method = object["method"]?.stringValue,
              let payload = object["payload"],
              object.count == 5
        else {
            throw CSPError(code: .invalidRequest, message: "Malformed sign_request body")
        }
        return CSPSignRequestBody(
            requestID: requestID, account: account, chain: chain, method: method, payload: payload)
    }
}

// MARK: - Sign response body (§9.4)

public enum CSPSignResponseBody: Equatable {
    case signedTransaction(requestID: String, rawTransaction: String)
    case signature(requestID: String, signature: String)
    case failure(requestID: String, error: CSPError)

    public var requestID: String {
        switch self {
        case .signedTransaction(let id, _), .signature(let id, _), .failure(let id, _):
            return id
        }
    }

    public func encode() -> Data {
        var object: [String: CSPJSON] = ["request_id": .string(requestID)]
        switch self {
        case .signedTransaction(_, let raw):
            object["result"] = .object(["signedTransaction": .string(raw)])
        case .signature(_, let signature):
            object["result"] = .object(["signature": .string(signature)])
        case .failure(_, let error):
            object["error"] = .object([
                "code": .string(error.code.rawValue),
                "message": .string(error.message),
            ])
        }
        return CSPJSON.object(object).canonicalData()
    }

    public static func decode(_ data: Data) throws -> CSPSignResponseBody {
        let object = try CSPJSON.parseObject(data)
        guard let requestID = object["request_id"]?.stringValue else {
            throw CSPError(code: .invalidRequest, message: "Missing request_id")
        }
        if let result = object["result"]?.objectValue {
            if let raw = result["signedTransaction"]?.stringValue {
                return .signedTransaction(requestID: requestID, rawTransaction: raw)
            }
            if let signature = result["signature"]?.stringValue {
                return .signature(requestID: requestID, signature: signature)
            }
            throw CSPError(code: .invalidRequest, message: "Malformed result")
        }
        if let error = object["error"]?.objectValue,
           let codeString = error["code"]?.stringValue,
           let code = CSPErrorCode(rawValue: codeString) {
            return .failure(
                requestID: requestID,
                error: CSPError(code: code, message: error["message"]?.stringValue ?? ""))
        }
        throw CSPError(code: .invalidRequest, message: "Neither result nor error present")
    }
}

// MARK: - Grants body codec (§7.3, §8)

public enum CSPGrantsBody {
    public static func encode(_ grantSet: CSPGrantSet) -> Data {
        let grants = grantSet.grants.map { grant in
            CSPJSON.object([
                "account": .string(grant.account),
                "chains": .array(grant.chains.map(CSPJSON.string)),
            ])
        }
        let object: [String: CSPJSON] = [
            "grants": .array(grants),
            "methods": .array(grantSet.methods.map(CSPJSON.string)),
            "limits": .object([
                "max_envelope_bytes": .int(Int64(CSPLimits.maxEnvelopeBytes)),
                "max_pending_sign": .int(Int64(CSPLimits.maxPendingSignRequests)),
            ]),
        ]
        return CSPJSON.object(object).canonicalData()
    }

    public static func decode(_ data: Data) throws -> CSPGrantSet {
        let object = try CSPJSON.parseObject(data)
        guard let rawGrants = object["grants"]?.arrayValue,
              let rawMethods = object["methods"]?.arrayValue
        else {
            throw CSPError(code: .invalidRequest, message: "Malformed grants body")
        }
        let grants: [CSPGrant] = try rawGrants.map { entry in
            guard let entryObject = entry.objectValue,
                  let account = entryObject["account"]?.stringValue,
                  let chains = entryObject["chains"]?.arrayValue?.compactMap(\.stringValue)
            else {
                throw CSPError(code: .invalidRequest, message: "Malformed grant entry")
            }
            return CSPGrant(account: account, chains: chains)
        }
        let methods = rawMethods.compactMap(\.stringValue)
        return CSPGrantSet(grants: grants, methods: methods)
    }
}
