//
//  CSPIntegratorSession.swift
//  Cryptograph
//
//  Integrator-side (peer wallet) implementation of the Cryptograph Signer
//  Protocol v1. This is the reference client: the native sample app uses it
//  directly, and the unit tests run full pair→sign transcripts by wiring it
//  to CSPRelayEngine in-process. Third-party TypeScript integrators use the
//  equivalent @perpetua/signer-protocol SDK.
//
//  See docs/SIGNER_PROTOCOL.md.
//

import CryptoKit
import Foundation

/// State held between sending a pair_request and receiving the callback.
public struct CSPIntegratorPendingPair: Codable, Equatable {
    public let keys: CSPKeyPairSet
    public let callbackURL: String
    public let noncePeer: Data
    /// SHA-256 of the canonical pair_request envelope we sent.
    public let requestHash: Data
    public let createdAt: Date
}

/// A completed pairing from the integrator's perspective.
public struct CSPIntegratorPairing: Codable, Equatable {
    public let pairingID: String
    public let callbackURL: String
    public var keys: CSPKeyPairSet
    /// Pinned Cryptograph keys (SEC1 compressed).
    public var cryptographSigningPublicKey: Data
    public var cryptographKEMPublicKey: Data
    public var grants: CSPGrantSet
    /// Last used outbound counter (integrator → relay).
    public var outboundCounter: Int64
    /// Highest verified inbound counter (relay → integrator).
    public var inboundCounter: Int64
    public let createdAt: Date
}

/// Events produced by handling a callback URL from Cryptograph.
public enum CSPIntegratorEvent: Equatable {
    case paired(CSPIntegratorPairing)
    case pairDeclined
    case accounts(CSPGrantSet, pairing: CSPIntegratorPairing)
    case signResult(CSPSignResponseBody, pairing: CSPIntegratorPairing)
    case revoked(pairing: CSPIntegratorPairing)
    case keysRotated(pairing: CSPIntegratorPairing)
}

public enum CSPIntegratorError: Error, Equatable {
    case invalidCallback(String)
    case transcriptMismatch
    case unknownPairing
    case replayedCounter
    case invalidSignature
    case bodyDidNotUnseal
}

public enum CSPIntegratorSession {
    // MARK: - Pairing (§7)

    /// Creates a pair_request URL to open, plus the pending state to persist
    /// until the callback arrives.
    public static func makePairRequest(
        callbackURL: String,
        appName: String?,
        relayHost: String = CSPURLCodec.relayHost,
        now: Date = Date()
    ) throws -> (url: URL, pending: CSPIntegratorPendingPair) {
        guard let callback = CSPURLCodec.validateCallbackURL(callbackURL) else {
            throw CSPIntegratorError.invalidCallback("Callback URL fails §7.1 rules")
        }
        let keys = CSPKeyPairSet()
        var nonce = Data(count: 32)
        _ = nonce.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }

        var fields: [String: CSPJSON] = [
            "cb": .string(callback.absoluteString),
            "peer_sig_pub": .string(keys.signingPublicKey.base64URLEncoded),
            "peer_kem_pub": .string(keys.kemPublicKey.base64URLEncoded),
            "nonce_peer": .string(nonce.base64URLEncoded),
            "iat": .int(Int64(now.timeIntervalSince1970)),
            "exp": .int(Int64(now.timeIntervalSince1970) + 600),
        ]
        if let appName { fields["app_name"] = .string(appName) }
        let envelope = try CSPEnvelope.make(type: .pairRequest, fields: fields)

        let signature = try CSPCrypto.sign(
            input: envelope.signingInput(destinationHost: relayHost),
            with: keys.signingKey()
        )
        guard let base = URL(string: "https://\(relayHost)/pair") else {
            throw CSPError(code: .internalError, message: "Bad relay host")
        }
        let url = try CSPURLCodec.makeURL(
            base: base, envelope: envelope, signature: signature, asResponse: false)

        let pending = CSPIntegratorPendingPair(
            keys: keys,
            callbackURL: callback.absoluteString,
            noncePeer: nonce,
            requestHash: Data(SHA256.hash(data: envelope.canonicalData())),
            createdAt: now
        )
        return (url, pending)
    }

    /// Handles the pair_response callback. Returns `.paired` or `.pairDeclined`.
    public static func handlePairCallback(
        url: URL,
        pending: CSPIntegratorPendingPair,
        now: Date = Date()
    ) throws -> CSPIntegratorEvent {
        let message = try parseCallback(url: url, expectedCallback: pending.callbackURL)
        let envelope = message.envelope
        guard envelope.type == .pairResponse else {
            throw CSPIntegratorError.invalidCallback("Expected pair_response")
        }

        // Transcript binding: nonce echo + request hash (§7.3).
        guard envelope.base64URLField("nonce_peer") == pending.noncePeer,
              envelope.base64URLField("req_hash") == pending.requestHash
        else {
            throw CSPIntegratorError.transcriptMismatch
        }

        guard let cgSigPub = envelope.base64URLField("cg_sig_pub"), cgSigPub.count == 33 else {
            throw CSPIntegratorError.invalidCallback("Missing cg_sig_pub")
        }
        guard let callbackHost = URL(string: pending.callbackURL)?.host?.lowercased() else {
            throw CSPIntegratorError.invalidCallback("Pending callback URL lost its host")
        }
        // pair_response is signed by the key it carries (pinned from here on).
        guard CSPCrypto.verify(
            signature: message.signature,
            input: envelope.signingInput(destinationHost: callbackHost),
            publicKey: cgSigPub)
        else {
            throw CSPIntegratorError.invalidSignature
        }

        if envelope.string("error") == CSPErrorCode.rejectedByUser.rawValue {
            return .pairDeclined
        }

        guard let pairingID = envelope.pairingID,
              let cgKemPub = envelope.base64URLField("cg_kem_pub"), cgKemPub.count == 33,
              envelope.base64URLField("nonce_cg")?.count == 32,
              let sealed = envelope.sealedBody
        else {
            throw CSPIntegratorError.invalidCallback("Malformed pair_response")
        }

        let grantsData: Data
        do {
            grantsData = try CSPCrypto.open(
                sealed,
                with: pending.keys.kemKey(),
                type: CSPMessageType.pairResponse.rawValue,
                pairingID: pairingID,
                ctr: 0
            )
        } catch {
            throw CSPIntegratorError.bodyDidNotUnseal
        }
        let grants = try CSPGrantsBody.decode(grantsData)

        return .paired(CSPIntegratorPairing(
            pairingID: pairingID,
            callbackURL: pending.callbackURL,
            keys: pending.keys,
            cryptographSigningPublicKey: cgSigPub,
            cryptographKEMPublicKey: cgKemPub,
            grants: grants,
            outboundCounter: 0,
            inboundCounter: 0,
            createdAt: now
        ))
    }

    // MARK: - Requests (§8, §9)

    /// Builds an accounts_request URL. Returns the URL and the pairing with
    /// the advanced outbound counter — persist before opening.
    public static func makeAccountsRequest(
        pairing: CSPIntegratorPairing,
        relayHost: String = CSPURLCodec.relayHost,
        now: Date = Date()
    ) throws -> (url: URL, pairing: CSPIntegratorPairing) {
        var pairing = pairing
        pairing.outboundCounter += 1
        let nowSeconds = Int64(now.timeIntervalSince1970)
        let envelope = try CSPEnvelope.make(type: .accountsRequest, fields: [
            "pairing_id": .string(pairing.pairingID),
            "ctr": .int(pairing.outboundCounter),
            "iat": .int(nowSeconds),
            "exp": .int(nowSeconds + 300),
        ])
        let url = try requestURL(
            envelope: envelope, pairing: pairing, path: "/accounts", relayHost: relayHost)
        return (url, pairing)
    }

    /// Builds a sign_request URL for an EVM method. Returns the URL and the
    /// pairing with the advanced outbound counter — persist before opening.
    public static func makeSignRequest(
        pairing: CSPIntegratorPairing,
        body: CSPSignRequestBody,
        relayHost: String = CSPURLCodec.relayHost,
        lifetimeSeconds: Int64 = 300,
        now: Date = Date()
    ) throws -> (url: URL, pairing: CSPIntegratorPairing) {
        var pairing = pairing
        pairing.outboundCounter += 1
        let sealed = try CSPCrypto.seal(
            try body.encode(),
            to: pairing.cryptographKEMPublicKey,
            type: CSPMessageType.signRequest.rawValue,
            pairingID: pairing.pairingID,
            ctr: pairing.outboundCounter
        )
        let nowSeconds = Int64(now.timeIntervalSince1970)
        let envelope = try CSPEnvelope.make(type: .signRequest, fields: [
            "pairing_id": .string(pairing.pairingID),
            "ctr": .int(pairing.outboundCounter),
            "iat": .int(nowSeconds),
            "exp": .int(nowSeconds + min(lifetimeSeconds, CSPLimits.maxSignRequestLifetimeSeconds)),
            "body": .string(sealed.base64URLEncoded),
        ])
        let url = try requestURL(
            envelope: envelope, pairing: pairing, path: "/sign", relayHost: relayHost)
        return (url, pairing)
    }

    /// Handles any post-pairing callback from Cryptograph.
    public static func handleCallback(
        url: URL,
        pairing: CSPIntegratorPairing
    ) throws -> CSPIntegratorEvent {
        let message = try parseCallback(url: url, expectedCallback: pairing.callbackURL)
        let envelope = message.envelope
        guard envelope.pairingID == pairing.pairingID else {
            throw CSPIntegratorError.unknownPairing
        }
        guard let callbackHost = URL(string: pairing.callbackURL)?.host?.lowercased() else {
            throw CSPIntegratorError.invalidCallback("Pairing callback URL lost its host")
        }
        guard CSPCrypto.verify(
            signature: message.signature,
            input: envelope.signingInput(destinationHost: callbackHost),
            publicKey: pairing.cryptographSigningPublicKey)
        else {
            throw CSPIntegratorError.invalidSignature
        }
        guard let counter = envelope.counter, counter > pairing.inboundCounter else {
            throw CSPIntegratorError.replayedCounter
        }
        var pairing = pairing
        pairing.inboundCounter = counter

        switch envelope.type {
        case .accountsResponse:
            let body = try unseal(envelope: envelope, pairing: pairing, counter: counter)
            let grants = try CSPGrantsBody.decode(body)
            pairing.grants = grants
            return .accounts(grants, pairing: pairing)
        case .signResponse:
            let body = try unseal(envelope: envelope, pairing: pairing, counter: counter)
            let response = try CSPSignResponseBody.decode(body)
            return .signResult(response, pairing: pairing)
        case .revoke:
            return .revoked(pairing: pairing)
        case .rotateKey:
            let body = try unseal(envelope: envelope, pairing: pairing, counter: counter)
            let object = try CSPJSON.parseObject(body)
            let newSigPub = object["new_sig_pub"]?.stringValue.flatMap { Data(base64URLEncoded: $0) }
            let newKemPub = object["new_kem_pub"]?.stringValue.flatMap { Data(base64URLEncoded: $0) }
            guard let proofEncoded = object["proof"]?.stringValue,
                  let proof = Data(base64URLEncoded: proofEncoded),
                  newSigPub != nil || newKemPub != nil
            else {
                throw CSPIntegratorError.invalidCallback("Malformed rotate_key body")
            }
            let proofInput = CSPCrypto.rotationProofInput(
                pairingID: pairing.pairingID, ctr: counter,
                newSigPub: newSigPub, newKemPub: newKemPub)
            let proofKey = newSigPub ?? pairing.cryptographSigningPublicKey
            guard CSPCrypto.verify(signature: proof, input: proofInput, publicKey: proofKey) else {
                throw CSPIntegratorError.invalidSignature
            }
            if let newSigPub { pairing.cryptographSigningPublicKey = newSigPub }
            if let newKemPub { pairing.cryptographKEMPublicKey = newKemPub }
            return .keysRotated(pairing: pairing)
        default:
            throw CSPIntegratorError.invalidCallback("Unexpected callback type \(envelope.type.rawValue)")
        }
    }

    // MARK: - Helpers

    private static func parseCallback(url: URL, expectedCallback: String) throws -> CSPURLCodec.Message {
        guard let expected = URL(string: expectedCallback),
              url.host?.lowercased() == expected.host?.lowercased(),
              url.path == expected.path
        else {
            throw CSPIntegratorError.invalidCallback("Callback host/path mismatch")
        }
        let message = try CSPURLCodec.parse(url)
        guard message.isResponse else {
            throw CSPIntegratorError.invalidCallback("Expected res parameter")
        }
        return message
    }

    private static func unseal(
        envelope: CSPEnvelope,
        pairing: CSPIntegratorPairing,
        counter: Int64
    ) throws -> Data {
        guard let sealed = envelope.sealedBody else {
            throw CSPIntegratorError.invalidCallback("Missing body")
        }
        do {
            return try CSPCrypto.open(
                sealed,
                with: pairing.keys.kemKey(),
                type: envelope.type.rawValue,
                pairingID: pairing.pairingID,
                ctr: counter
            )
        } catch {
            throw CSPIntegratorError.bodyDidNotUnseal
        }
    }

    private static func requestURL(
        envelope: CSPEnvelope,
        pairing: CSPIntegratorPairing,
        path: String,
        relayHost: String
    ) throws -> URL {
        let signature = try CSPCrypto.sign(
            input: envelope.signingInput(destinationHost: relayHost),
            with: pairing.keys.signingKey()
        )
        guard let base = URL(string: "https://\(relayHost)\(path)") else {
            throw CSPError(code: .internalError, message: "Bad relay host")
        }
        return try CSPURLCodec.makeURL(
            base: base, envelope: envelope, signature: signature, asResponse: false)
    }
}
