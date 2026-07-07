//
//  CSPRelayEngine.swift
//  Cryptograph
//
//  Relay-side (Cryptograph iPhone app) validation pipeline and response
//  builders for the Cryptograph Signer Protocol v1.
//  See docs/SIGNER_PROTOCOL.md §6 (validation order), §7–§11.
//
//  This engine is pure: it never touches persistence or UI. Callers pass the
//  current pairing table and persist the updated records the engine returns.
//  The ordering guarantee that matters for security: the inbound counter
//  advances once signature verification succeeds, even when a later step
//  fails, so a signed-but-invalid message cannot be replayed.
//

import CryptoKit
import Foundation

public enum CSPTransport: Equatable {
    case universalLink
    case customScheme
}

/// Parsed cleartext content of a valid pair_request, for the consent UI.
public struct CSPPairRequestData: Equatable {
    public let callbackURL: URL
    public let peerDomain: String
    public let appName: String?
    public let peerSigningPublicKey: Data
    public let peerKEMPublicKey: Data
    public let noncePeer: Data
    /// SHA-256 of the canonical pair_request envelope (transcript hash).
    public let requestHash: Data
}

public enum CSPRelayOutcome: Equatable {
    /// Valid pair_request — present the consent flow.
    case pairRequest(CSPPairRequestData)
    /// Authenticated accounts_request — respond with current grants.
    case accountsRequest(pairing: CSPPairingRecord)
    /// Authenticated, granted sign_request — build the signing intent.
    case signRequest(pairing: CSPPairingRecord, body: CSPSignRequestBody)
    /// Authenticated revoke — mark revoked (record already updated).
    case revoke(pairing: CSPPairingRecord)
    /// Authenticated rotate_key — keys already rotated in the returned record.
    case rotateKey(pairing: CSPPairingRecord)
    /// Authenticated message that failed a post-signature step: send a signed
    /// error to the pairing's callback. `requestID` is set when the sealed
    /// body was readable enough to correlate.
    case errorResponse(pairing: CSPPairingRecord, error: CSPError, requestID: String?)
    /// Unauthenticated or malformed: no callback may be opened (§6).
    case silentDrop(reason: String)
}

public enum CSPRelayEngine {
    /// SHA-256 over canonical envelope bytes, for pair transcript binding.
    public static func requestHash(of envelope: CSPEnvelope) -> Data {
        Data(SHA256.hash(data: envelope.canonicalData()))
    }

    // MARK: - Inbound validation (§6)

    public static func handle(
        url: URL,
        transport: CSPTransport,
        pairings: [CSPPairingRecord],
        now: Date = Date()
    ) -> CSPRelayOutcome {
        // Step 1: transport.
        guard transport == .universalLink else {
            return .silentDrop(reason: "Signer message over custom scheme")
        }
        guard url.scheme == "https",
              url.host?.lowercased() == CSPURLCodec.relayHost
        else {
            return .silentDrop(reason: "Signer message delivered to non-relay host")
        }
        guard let expectedType = CSPMessageType.expectedType(forPath: url.path) else {
            return .silentDrop(reason: "Unknown endpoint \(url.path)")
        }

        // Step 2: envelope shape.
        let message: CSPURLCodec.Message
        do {
            message = try CSPURLCodec.parse(url)
        } catch {
            return .silentDrop(reason: "Malformed message: \(error)")
        }
        let envelope = message.envelope
        guard !message.isResponse, envelope.type == expectedType else {
            return .silentDrop(reason: "Type/endpoint mismatch")
        }

        if envelope.type == .pairRequest {
            return handlePairRequest(envelope: envelope, signature: message.signature,
                                     pairings: pairings, now: now)
        }

        // Step 3: pairing exists and is live.
        guard let pairingID = envelope.pairingID,
              var pairing = pairings.first(where: { $0.id == pairingID })
        else {
            return .silentDrop(reason: "Unknown pairing")
        }
        guard pairing.status != .revoked else {
            return .silentDrop(reason: "Revoked pairing")
        }
        if pairing.isExpiredProvisional {
            return .silentDrop(reason: "Expired provisional pairing")
        }

        // Step 4: signature over canonical envelope + our host.
        let signingInput = envelope.signingInput(destinationHost: CSPURLCodec.relayHost)
        guard CSPCrypto.verify(
            signature: message.signature,
            input: signingInput,
            publicKey: pairing.peerSigningPublicKey)
        else {
            return .silentDrop(reason: "Invalid signature")
        }

        // Step 5: counter. Advancing consumes the counter even if later
        // steps fail — a signed, replay-protected message was seen.
        guard let counter = envelope.counter, counter > pairing.inboundCounter else {
            return .silentDrop(reason: "Replayed counter")
        }
        pairing.inboundCounter = counter
        pairing.lastUsedAt = now
        // First authenticated message activates a provisional pairing (§7.4).
        if pairing.status == .provisional {
            pairing.status = .active
        }

        // Step 6: time window.
        let nowSeconds = Int64(now.timeIntervalSince1970)
        if let issuedAt = envelope.issuedAt,
           issuedAt > nowSeconds + CSPLimits.clockSkewSeconds {
            return .errorResponse(pairing: pairing,
                                  error: CSPError(code: .expired, message: "iat in the future"),
                                  requestID: nil)
        }
        if let expiry = envelope.expiry {
            guard expiry >= nowSeconds else {
                return .errorResponse(pairing: pairing,
                                      error: CSPError(code: .expired, message: "Request expired"),
                                      requestID: nil)
            }
            if envelope.type == .signRequest, let issuedAt = envelope.issuedAt,
               expiry - issuedAt > CSPLimits.maxSignRequestLifetimeSeconds {
                return .errorResponse(pairing: pairing,
                                      error: CSPError(code: .invalidRequest,
                                                      message: "sign_request lifetime exceeds \(CSPLimits.maxSignRequestLifetimeSeconds)s"),
                                      requestID: nil)
            }
        }

        // Steps 7–8: body and content rules, per type.
        switch envelope.type {
        case .accountsRequest:
            return .accountsRequest(pairing: pairing)
        case .signRequest:
            return handleSignRequest(envelope: envelope, pairing: pairing, counter: counter)
        case .revoke:
            pairing.status = .revoked
            return .revoke(pairing: pairing)
        case .rotateKey:
            return handleRotateKey(envelope: envelope, pairing: pairing, counter: counter)
        default:
            return .silentDrop(reason: "Unexpected type after validation")
        }
    }

    private static func handlePairRequest(
        envelope: CSPEnvelope,
        signature: Data,
        pairings: [CSPPairingRecord],
        now: Date
    ) -> CSPRelayOutcome {
        guard let callbackString = envelope.string("cb"),
              let callbackURL = CSPURLCodec.validateCallbackURL(callbackString),
              let host = callbackURL.host?.lowercased(),
              let peerSigPub = envelope.base64URLField("peer_sig_pub"), peerSigPub.count == 33,
              let peerKemPub = envelope.base64URLField("peer_kem_pub"), peerKemPub.count == 33,
              let noncePeer = envelope.base64URLField("nonce_peer"), noncePeer.count == 32
        else {
            return .silentDrop(reason: "Malformed pair_request fields")
        }

        // Self-signed proof of possession (§7.1).
        let signingInput = envelope.signingInput(destinationHost: CSPURLCodec.relayHost)
        guard CSPCrypto.verify(signature: signature, input: signingInput, publicKey: peerSigPub) else {
            return .silentDrop(reason: "pair_request proof-of-possession failed")
        }

        // Time window (self-asserted, but bounds consent-sheet replay).
        let nowSeconds = Int64(now.timeIntervalSince1970)
        guard let expiry = envelope.expiry, expiry >= nowSeconds,
              let issuedAt = envelope.issuedAt,
              issuedAt <= nowSeconds + CSPLimits.clockSkewSeconds
        else {
            return .silentDrop(reason: "pair_request outside time window")
        }

        // Re-pairing with identical identity requires fresh consent, which is
        // exactly what presenting the sheet does — but never silently while a
        // live pairing exists for the same key (§6 step 3).
        let duplicate = pairings.contains {
            $0.status != .revoked && $0.peerDomain == host
                && $0.peerSigningPublicKey == peerSigPub
        }
        guard !duplicate else {
            return .silentDrop(reason: "Live pairing already exists for this peer key")
        }

        return .pairRequest(CSPPairRequestData(
            callbackURL: callbackURL,
            peerDomain: host,
            appName: envelope.string("app_name"),
            peerSigningPublicKey: peerSigPub,
            peerKEMPublicKey: peerKemPub,
            noncePeer: noncePeer,
            requestHash: requestHash(of: envelope)
        ))
    }

    private static func handleSignRequest(
        envelope: CSPEnvelope,
        pairing: CSPPairingRecord,
        counter: Int64
    ) -> CSPRelayOutcome {
        guard let sealed = envelope.sealedBody else {
            return .errorResponse(pairing: pairing,
                                  error: CSPError(code: .invalidRequest, message: "Missing body"),
                                  requestID: nil)
        }
        let plaintext: Data
        do {
            plaintext = try CSPCrypto.open(
                sealed,
                with: pairing.localKeys.kemKey(),
                type: envelope.type.rawValue,
                pairingID: pairing.id,
                ctr: counter
            )
        } catch {
            return .errorResponse(pairing: pairing,
                                  error: CSPError(code: .decodeFailed, message: "Body did not unseal"),
                                  requestID: nil)
        }

        let body: CSPSignRequestBody
        do {
            body = try CSPSignRequestBody.decode(plaintext)
        } catch {
            return .errorResponse(pairing: pairing,
                                  error: CSPError(code: .invalidRequest, message: "Malformed sign body"),
                                  requestID: nil)
        }

        guard let normalizedMethod = body.normalizedMethod,
              pairing.grants.methods.contains(normalizedMethod)
        else {
            return .errorResponse(pairing: pairing,
                                  error: CSPError(code: .unsupportedMethod,
                                                  message: "Method \(body.method) not supported"),
                                  requestID: body.requestID)
        }
        guard AddressValidator.validateEVMAddress(body.account) == nil else {
            return .errorResponse(pairing: pairing,
                                  error: CSPError(code: .invalidRequest,
                                                  message: "Account fails EVM address/EIP-55 validation"),
                                  requestID: body.requestID)
        }
        guard body.chain.hasPrefix("eip155:") else {
            return .errorResponse(pairing: pairing,
                                  error: CSPError(code: .invalidRequest,
                                                  message: "v1 supports eip155 chains only"),
                                  requestID: body.requestID)
        }
        guard pairing.grants.allows(account: body.account, chain: body.chain) else {
            return .errorResponse(pairing: pairing,
                                  error: CSPError(code: .grantViolation,
                                                  message: "Account/chain not granted"),
                                  requestID: body.requestID)
        }

        return .signRequest(pairing: pairing, body: body)
    }

    private static func handleRotateKey(
        envelope: CSPEnvelope,
        pairing: CSPPairingRecord,
        counter: Int64
    ) -> CSPRelayOutcome {
        var pairing = pairing
        guard let sealed = envelope.sealedBody,
              let plaintext = try? CSPCrypto.open(
                sealed,
                with: pairing.localKeys.kemKey(),
                type: envelope.type.rawValue,
                pairingID: pairing.id,
                ctr: counter),
              let object = try? CSPJSON.parseObject(plaintext)
        else {
            return .errorResponse(pairing: pairing,
                                  error: CSPError(code: .decodeFailed, message: "rotate_key body did not unseal"),
                                  requestID: nil)
        }

        let newSigPub = object["new_sig_pub"]?.stringValue.flatMap { Data(base64URLEncoded: $0) }
        let newKemPub = object["new_kem_pub"]?.stringValue.flatMap { Data(base64URLEncoded: $0) }
        guard newSigPub != nil || newKemPub != nil,
              newSigPub.map({ $0.count == 33 }) ?? true,
              newKemPub.map({ $0.count == 33 }) ?? true,
              let proofEncoded = object["proof"]?.stringValue,
              let proof = Data(base64URLEncoded: proofEncoded)
        else {
            return .errorResponse(pairing: pairing,
                                  error: CSPError(code: .invalidRequest, message: "Malformed rotate_key body"),
                                  requestID: nil)
        }

        // Possession proof by the NEW signature key (or current one when only
        // the KEM key rotates). Envelope signature by the old key was already
        // verified upstream.
        let proofKey = newSigPub ?? pairing.peerSigningPublicKey
        let proofInput = CSPCrypto.rotationProofInput(
            pairingID: pairing.id, ctr: counter, newSigPub: newSigPub, newKemPub: newKemPub)
        guard CSPCrypto.verify(signature: proof, input: proofInput, publicKey: proofKey) else {
            return .errorResponse(pairing: pairing,
                                  error: CSPError(code: .invalidSignature, message: "Rotation proof failed"),
                                  requestID: nil)
        }

        if let newSigPub { pairing.peerSigningPublicKey = newSigPub }
        if let newKemPub { pairing.peerKEMPublicKey = newKemPub }
        return .rotateKey(pairing: pairing)
    }

    // MARK: - Outbound responses (relay → integrator callback)

    /// Result of building an outbound message: the URL to open and the
    /// pairing record with the advanced outbound counter, to persist first.
    public struct OutboundMessage: Equatable {
        public let url: URL
        public let pairing: CSPPairingRecord
    }

    /// Successful pair_response (§7.3). The returned record starts provisional.
    public static func makePairResponse(
        accepted request: CSPPairRequestData,
        grants: CSPGrantSet,
        now: Date = Date()
    ) throws -> OutboundMessage {
        let pairing = CSPPairingRecord(
            peerDomain: request.peerDomain,
            callbackURL: request.callbackURL.absoluteString,
            appName: request.appName,
            peerSigningPublicKey: request.peerSigningPublicKey,
            peerKEMPublicKey: request.peerKEMPublicKey,
            grants: grants,
            createdAt: now,
            lastUsedAt: now
        )

        var nonceCG = Data(count: 32)
        _ = nonceCG.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }

        let sealedGrants = try CSPCrypto.seal(
            CSPGrantsBody.encode(grants),
            to: request.peerKEMPublicKey,
            type: CSPMessageType.pairResponse.rawValue,
            pairingID: pairing.id,
            ctr: 0
        )

        let envelope = try CSPEnvelope.make(type: .pairResponse, fields: [
            "pairing_id": .string(pairing.id),
            "cg_sig_pub": .string(pairing.localKeys.signingPublicKey.base64URLEncoded),
            "cg_kem_pub": .string(pairing.localKeys.kemPublicKey.base64URLEncoded),
            "nonce_peer": .string(request.noncePeer.base64URLEncoded),
            "nonce_cg": .string(nonceCG.base64URLEncoded),
            "req_hash": .string(request.requestHash.base64URLEncoded),
            "iat": .int(Int64(now.timeIntervalSince1970)),
            "body": .string(sealedGrants.base64URLEncoded),
        ])

        let url = try signedURL(envelope: envelope, pairing: pairing)
        return OutboundMessage(url: url, pairing: pairing)
    }

    /// Declined pair_response (§7.3): self-signed, no pairing established.
    public static func makePairDecline(
        request: CSPPairRequestData,
        now: Date = Date()
    ) throws -> URL {
        let keys = CSPKeyPairSet()
        let envelope = try CSPEnvelope.make(type: .pairResponse, fields: [
            "cg_sig_pub": .string(keys.signingPublicKey.base64URLEncoded),
            "nonce_peer": .string(request.noncePeer.base64URLEncoded),
            "req_hash": .string(request.requestHash.base64URLEncoded),
            "error": .string(CSPErrorCode.rejectedByUser.rawValue),
            "iat": .int(Int64(now.timeIntervalSince1970)),
        ])
        guard let host = request.callbackURL.host?.lowercased() else {
            throw CSPError(code: .internalError, message: "Callback URL lost its host")
        }
        let signature = try CSPCrypto.sign(
            input: envelope.signingInput(destinationHost: host),
            with: keys.signingKey()
        )
        return try CSPURLCodec.makeURL(
            base: request.callbackURL, envelope: envelope, signature: signature, asResponse: true)
    }

    /// accounts_response carrying current grants (§8).
    public static func makeAccountsResponse(
        pairing: CSPPairingRecord,
        now: Date = Date()
    ) throws -> OutboundMessage {
        var pairing = pairing
        pairing.outboundCounter += 1
        let sealed = try CSPCrypto.seal(
            CSPGrantsBody.encode(pairing.grants),
            to: pairing.peerKEMPublicKey,
            type: CSPMessageType.accountsResponse.rawValue,
            pairingID: pairing.id,
            ctr: pairing.outboundCounter
        )
        let envelope = try CSPEnvelope.make(type: .accountsResponse, fields: [
            "pairing_id": .string(pairing.id),
            "ctr": .int(pairing.outboundCounter),
            "iat": .int(Int64(now.timeIntervalSince1970)),
            "body": .string(sealed.base64URLEncoded),
        ])
        let url = try signedURL(envelope: envelope, pairing: pairing)
        return OutboundMessage(url: url, pairing: pairing)
    }

    /// sign_response for a completed, failed, or rejected request (§9.4).
    public static func makeSignResponse(
        pairing: CSPPairingRecord,
        body: CSPSignResponseBody,
        now: Date = Date()
    ) throws -> OutboundMessage {
        var pairing = pairing
        pairing.outboundCounter += 1
        let sealed = try CSPCrypto.seal(
            body.encode(),
            to: pairing.peerKEMPublicKey,
            type: CSPMessageType.signResponse.rawValue,
            pairingID: pairing.id,
            ctr: pairing.outboundCounter
        )
        let envelope = try CSPEnvelope.make(type: .signResponse, fields: [
            "pairing_id": .string(pairing.id),
            "ctr": .int(pairing.outboundCounter),
            "iat": .int(Int64(now.timeIntervalSince1970)),
            "body": .string(sealed.base64URLEncoded),
        ])
        let url = try signedURL(envelope: envelope, pairing: pairing)
        return OutboundMessage(url: url, pairing: pairing)
    }

    /// Courtesy revoke notification to the integrator (§11).
    public static func makeRevoke(
        pairing: CSPPairingRecord,
        now: Date = Date()
    ) throws -> OutboundMessage {
        var pairing = pairing
        pairing.outboundCounter += 1
        pairing.status = .revoked
        let envelope = try CSPEnvelope.make(type: .revoke, fields: [
            "pairing_id": .string(pairing.id),
            "ctr": .int(pairing.outboundCounter),
            "iat": .int(Int64(now.timeIntervalSince1970)),
        ])
        let url = try signedURL(envelope: envelope, pairing: pairing)
        return OutboundMessage(url: url, pairing: pairing)
    }

    private static func signedURL(envelope: CSPEnvelope, pairing: CSPPairingRecord) throws -> URL {
        guard let callbackURL = URL(string: pairing.callbackURL),
              let host = callbackURL.host?.lowercased()
        else {
            throw CSPError(code: .internalError, message: "Pairing callback URL is invalid")
        }
        let signature = try CSPCrypto.sign(
            input: envelope.signingInput(destinationHost: host),
            with: pairing.localKeys.signingKey()
        )
        return try CSPURLCodec.makeURL(
            base: callbackURL, envelope: envelope, signature: signature, asResponse: true)
    }
}
