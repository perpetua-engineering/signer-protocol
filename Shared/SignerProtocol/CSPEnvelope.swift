//
//  CSPEnvelope.swift
//  Cryptograph
//
//  Envelope model, strict field validation, and URL codec for the
//  Cryptograph Signer Protocol v1. See docs/SIGNER_PROTOCOL.md §5–§6.
//
//  Envelopes are deliberately strict: unknown fields are rejected, required
//  fields are per-type, and the canonical serialization is the signed surface.
//

import Foundation

/// A parsed and shape-validated protocol envelope. Field semantics (counters,
/// expiry windows, key pinning) are enforced by CSPRelayValidator /
/// CSPIntegratorSession, not here.
public struct CSPEnvelope: Equatable {
    public let type: CSPMessageType
    public let object: [String: CSPJSON]

    public static let version: Int64 = 1

    // MARK: - Field access

    public func string(_ key: String) -> String? { object[key]?.stringValue }
    public func int(_ key: String) -> Int64? { object[key]?.intValue }

    public var pairingID: String? { string("pairing_id") }
    public var counter: Int64? { int("ctr") }
    public var issuedAt: Int64? { int("iat") }
    public var expiry: Int64? { int("exp") }

    /// Decoded `body` field (base64url of `enc ‖ ct`).
    public var sealedBody: Data? {
        guard let encoded = string("body") else { return nil }
        return Data(base64URLEncoded: encoded)
    }

    public func base64URLField(_ key: String) -> Data? {
        guard let encoded = string(key) else { return nil }
        return Data(base64URLEncoded: encoded)
    }

    // MARK: - Shape rules

    /// required/optional cleartext fields per message type, beyond `v`/`type`.
    private static let fieldRules: [CSPMessageType: (required: Set<String>, optional: Set<String>)] = [
        .pairRequest: (
            required: ["cb", "peer_sig_pub", "peer_kem_pub", "nonce_peer", "iat", "exp"],
            optional: ["app_name"]
        ),
        .pairResponse: (
            required: ["nonce_peer", "req_hash", "cg_sig_pub", "iat"],
            optional: ["pairing_id", "cg_kem_pub", "nonce_cg", "body", "error"]
        ),
        .accountsRequest: (
            required: ["pairing_id", "ctr", "iat", "exp"],
            optional: []
        ),
        .accountsResponse: (
            required: ["pairing_id", "ctr", "iat", "body"],
            optional: []
        ),
        .signRequest: (
            required: ["pairing_id", "ctr", "iat", "exp", "body"],
            optional: []
        ),
        .signResponse: (
            required: ["pairing_id", "ctr", "iat", "body"],
            optional: []
        ),
        .revoke: (
            required: ["pairing_id", "ctr", "iat"],
            optional: ["exp"]
        ),
        .rotateKey: (
            required: ["pairing_id", "ctr", "iat", "body"],
            optional: ["exp"]
        ),
    ]

    // MARK: - Construction

    /// Builds an envelope from fields, injecting `v` and `type`.
    public static func make(type: CSPMessageType, fields: [String: CSPJSON]) throws -> CSPEnvelope {
        var object = fields
        object["v"] = .int(version)
        object["type"] = .string(type.rawValue)
        return try validate(object: object)
    }

    /// Parses and shape-validates envelope bytes.
    public static func parse(_ data: Data) throws -> CSPEnvelope {
        guard data.count <= CSPLimits.maxEnvelopeBytes else {
            throw CSPError(code: .payloadTooLarge, message: "Envelope exceeds \(CSPLimits.maxEnvelopeBytes) bytes")
        }
        let object: [String: CSPJSON]
        do {
            object = try CSPJSON.parseObject(data)
        } catch {
            throw CSPError(code: .invalidRequest, message: "Envelope is not valid CSP1 JSON")
        }
        return try validate(object: object)
    }

    private static func validate(object: [String: CSPJSON]) throws -> CSPEnvelope {
        guard let versionValue = object["v"]?.intValue else {
            throw CSPError(code: .invalidRequest, message: "Missing version")
        }
        guard versionValue == version else {
            throw CSPError(code: .unsupportedVersion, message: "Unsupported version \(versionValue)")
        }
        guard let typeString = object["type"]?.stringValue,
              let type = CSPMessageType(rawValue: typeString)
        else {
            throw CSPError(code: .invalidRequest, message: "Unknown message type")
        }
        guard let rules = fieldRules[type] else {
            throw CSPError(code: .invalidRequest, message: "Unknown message type")
        }

        let present = Set(object.keys).subtracting(["v", "type"])
        let missing = rules.required.subtracting(present)
        guard missing.isEmpty else {
            throw CSPError(code: .invalidRequest, message: "Missing fields: \(missing.sorted().joined(separator: ", "))")
        }
        let unknown = present.subtracting(rules.required).subtracting(rules.optional)
        guard unknown.isEmpty else {
            throw CSPError(code: .invalidRequest, message: "Unknown fields: \(unknown.sorted().joined(separator: ", "))")
        }

        // Envelope-level integers must be non-negative (§4.3).
        for key in ["ctr", "iat", "exp"] {
            if let value = object[key] {
                guard let intValue = value.intValue, intValue >= 0 else {
                    throw CSPError(code: .invalidRequest, message: "Field \(key) must be a non-negative integer")
                }
            }
        }

        return CSPEnvelope(type: type, object: object)
    }

    // MARK: - Canonical form and signing

    public func canonicalData() -> Data {
        CSPJSON.object(object).canonicalData()
    }

    /// The exact bytes a message signature covers (§6).
    public func signingInput(destinationHost: String) -> Data {
        CSPCrypto.signingInput(
            type: type.rawValue,
            destinationHost: destinationHost,
            canonicalEnvelope: canonicalData()
        )
    }
}

// MARK: - URL codec (§2.4)

public enum CSPURLCodec {
    public static let relayHost = "cryptograph.watch"
    public static let requestParameter = "req"
    public static let responseParameter = "res"
    public static let signatureParameter = "sig"

    public struct Message: Equatable {
        public let envelope: CSPEnvelope
        public let signature: Data
        /// True when the envelope arrived in `res` rather than `req`.
        public let isResponse: Bool
    }

    /// Builds a protocol message URL. `baseURL` is either a relay endpoint
    /// (`https://cryptograph.watch/sign`) or an integrator callback URL.
    public static func makeURL(
        base: URL,
        envelope: CSPEnvelope,
        signature: Data,
        asResponse: Bool
    ) throws -> URL {
        var components = URLComponents(url: base, resolvingAgainstBaseURL: false)
        components?.queryItems = [
            URLQueryItem(
                name: asResponse ? responseParameter : requestParameter,
                value: envelope.canonicalData().base64URLEncoded),
            URLQueryItem(name: signatureParameter, value: signature.base64URLEncoded),
        ]
        guard let url = components?.url else {
            throw CSPError(code: .internalError, message: "Failed to compose message URL")
        }
        guard url.absoluteString.utf8.count <= CSPLimits.maxURLBytes else {
            throw CSPError(code: .payloadTooLarge, message: "Message URL exceeds \(CSPLimits.maxURLBytes) bytes")
        }
        return url
    }

    /// Extracts and shape-validates the envelope and signature from an
    /// incoming Universal Link.
    public static func parse(_ url: URL) throws -> Message {
        guard url.absoluteString.utf8.count <= CSPLimits.maxURLBytes else {
            throw CSPError(code: .payloadTooLarge, message: "Message URL exceeds \(CSPLimits.maxURLBytes) bytes")
        }
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let queryItems = components.queryItems
        else {
            throw CSPError(code: .invalidRequest, message: "Missing query parameters")
        }

        var envelopeEncoded: String?
        var isResponse = false
        var signatureEncoded: String?
        for item in queryItems {
            switch item.name {
            case requestParameter:
                envelopeEncoded = item.value
                isResponse = false
            case responseParameter:
                envelopeEncoded = item.value
                isResponse = true
            case signatureParameter:
                signatureEncoded = item.value
            default:
                throw CSPError(code: .invalidRequest, message: "Unexpected query parameter \(item.name)")
            }
        }

        guard let envelopeEncoded,
              let envelopeData = Data(base64URLEncoded: envelopeEncoded),
              let signatureEncoded,
              let signature = Data(base64URLEncoded: signatureEncoded),
              signature.count == 64
        else {
            throw CSPError(code: .invalidRequest, message: "Malformed req/res or sig parameter")
        }

        let envelope = try CSPEnvelope.parse(envelopeData)
        return Message(envelope: envelope, signature: signature, isResponse: isResponse)
    }

    /// Validates a proposed callback URL per §7.1: https, host present, no
    /// query, no fragment, no IP literals or localhost, lowercase ASCII host.
    public static func validateCallbackURL(_ string: String) -> URL? {
        guard let url = URL(string: string),
              let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              components.scheme == "https",
              let host = components.host?.lowercased(),
              !host.isEmpty,
              components.query == nil,
              components.fragment == nil,
              components.user == nil,
              components.password == nil,
              components.port == nil
        else {
            return nil
        }
        // Reject IP literals and single-label hosts (incl. localhost).
        guard host.contains("."), host.allSatisfy({ $0.isASCII }) else { return nil }
        let labels = host.split(separator: ".")
        guard labels.count >= 2, !labels.allSatisfy({ $0.allSatisfy(\.isNumber) }) else { return nil }
        // The relay host itself can never be an integrator identity (endpoint
        // collision). Subdomains are allowed: only the relay operator can
        // associate apps with them, so they're reserved for first-party
        // demo/test integrators (e.g. demo.cryptograph.watch).
        guard host != relayHost else { return nil }
        return url
    }
}
