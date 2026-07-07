//
//  CSPCrypto.swift
//  Cryptograph
//
//  Cryptographic suite CSP1 for the Cryptograph Signer Protocol.
//  See docs/SIGNER_PROTOCOL.md §3, §5.1, §6.
//
//  - Message signatures: ECDSA P-256 / SHA-256, raw 64-byte r‖s.
//  - Body encryption: HPKE base mode, DHKEM(P-256, HKDF-SHA256) /
//    HKDF-SHA256 / AES-256-GCM (RFC 9180), single shot.
//
//  These keys are per-pairing transport identity keys. They are unrelated to
//  chain keys, which never leave the watch.
//

import CryptoKit
import Foundation

public enum CSPCryptoError: Error, Equatable {
    case invalidPublicKey
    case invalidSignature
    case invalidCiphertext
    case sealFailed(String)
    case openFailed(String)
}

public enum CSPCrypto {
    /// Domain-separation prefix for all CSP1 signing inputs.
    public static let protocolLabel = "CSP1"

    static let hpkeInfo = Data("CSP1 body".utf8)
    static let hpkeCiphersuite = HPKE.Ciphersuite.P256_SHA256_AES_GCM_256
    /// DHKEM(P-256) encapsulated keys are uncompressed SEC1 points.
    static let encapsulatedKeyLength = 65

    // MARK: - Signing input (§6)

    /// Builds the byte string that message signatures cover:
    /// `"CSP1|" + type + "|" + destinationHost + "|" + JCS(envelope)`.
    public static func signingInput(
        type: String,
        destinationHost: String,
        canonicalEnvelope: Data
    ) -> Data {
        var input = Data("\(protocolLabel)|\(type)|\(destinationHost)|".utf8)
        input.append(canonicalEnvelope)
        return input
    }

    public static func sign(input: Data, with key: P256.Signing.PrivateKey) throws -> Data {
        try key.signature(for: input).rawRepresentation
    }

    public static func verify(
        signature: Data,
        input: Data,
        publicKey compressedPublicKey: Data
    ) -> Bool {
        guard let key = try? P256.Signing.PublicKey(compressedRepresentation: compressedPublicKey),
              let ecdsaSignature = try? P256.Signing.ECDSASignature(rawRepresentation: signature)
        else {
            return false
        }
        return key.isValidSignature(ecdsaSignature, for: input)
    }

    // MARK: - Body sealing (§5.1)

    /// AAD binding a sealed body to its envelope position. `pair_response`
    /// precedes counters and uses ctr 0.
    static func bodyAAD(type: String, pairingID: String, ctr: Int64) -> Data {
        Data("\(protocolLabel)|\(type)|\(pairingID)|\(ctr)".utf8)
    }

    /// HPKE single-shot seal. Returns `enc ‖ ct`.
    public static func seal(
        _ plaintext: Data,
        to recipientCompressedKEMKey: Data,
        type: String,
        pairingID: String,
        ctr: Int64
    ) throws -> Data {
        guard let recipientKey = try? P256.KeyAgreement.PublicKey(
            compressedRepresentation: recipientCompressedKEMKey)
        else {
            throw CSPCryptoError.invalidPublicKey
        }
        do {
            var sender = try HPKE.Sender(
                recipientKey: recipientKey,
                ciphersuite: hpkeCiphersuite,
                info: hpkeInfo
            )
            let ciphertext = try sender.seal(
                plaintext,
                authenticating: bodyAAD(type: type, pairingID: pairingID, ctr: ctr)
            )
            return sender.encapsulatedKey + ciphertext
        } catch {
            throw CSPCryptoError.sealFailed(String(describing: error))
        }
    }

    /// HPKE single-shot open of `enc ‖ ct`.
    public static func open(
        _ sealed: Data,
        with privateKey: P256.KeyAgreement.PrivateKey,
        type: String,
        pairingID: String,
        ctr: Int64
    ) throws -> Data {
        guard sealed.count > encapsulatedKeyLength else {
            throw CSPCryptoError.invalidCiphertext
        }
        let encapsulated = sealed.prefix(encapsulatedKeyLength)
        let ciphertext = sealed.dropFirst(encapsulatedKeyLength)
        do {
            var recipient = try HPKE.Recipient(
                privateKey: privateKey,
                ciphersuite: hpkeCiphersuite,
                info: hpkeInfo,
                encapsulatedKey: encapsulated
            )
            return try recipient.open(
                ciphertext,
                authenticating: bodyAAD(type: type, pairingID: pairingID, ctr: ctr)
            )
        } catch {
            throw CSPCryptoError.openFailed(String(describing: error))
        }
    }

    // MARK: - Rotation proof (§11)

    /// Signing input for the `rotate_key` possession proof by the new key:
    /// `"CSP1 rotate" ‖ pairing_id ‖ ctr ‖ new_sig_pub ‖ new_kem_pub`,
    /// base64url fields joined with `|`. Absent keys contribute an empty field.
    public static func rotationProofInput(
        pairingID: String,
        ctr: Int64,
        newSigPub: Data?,
        newKemPub: Data?
    ) -> Data {
        let fields = [
            "\(protocolLabel) rotate",
            pairingID,
            String(ctr),
            newSigPub?.base64URLEncoded ?? "",
            newKemPub?.base64URLEncoded ?? "",
        ]
        return Data(fields.joined(separator: "|").utf8)
    }
}

// MARK: - Key material

/// One side's per-pairing key material: a P-256 signature key and a P-256 KEM
/// key. Codable for storage inside the (device-only, never-synchronized)
/// pairing record; see CSPPairingStore.
public struct CSPKeyPairSet: Codable, Equatable {
    public let signingPrivateKeyData: Data
    public let kemPrivateKeyData: Data

    public init() {
        signingPrivateKeyData = P256.Signing.PrivateKey().rawRepresentation
        kemPrivateKeyData = P256.KeyAgreement.PrivateKey().rawRepresentation
    }

    public init(signingPrivateKeyData: Data, kemPrivateKeyData: Data) {
        self.signingPrivateKeyData = signingPrivateKeyData
        self.kemPrivateKeyData = kemPrivateKeyData
    }

    public func signingKey() throws -> P256.Signing.PrivateKey {
        try P256.Signing.PrivateKey(rawRepresentation: signingPrivateKeyData)
    }

    public func kemKey() throws -> P256.KeyAgreement.PrivateKey {
        try P256.KeyAgreement.PrivateKey(rawRepresentation: kemPrivateKeyData)
    }

    /// SEC1 compressed signature public key (33 bytes).
    public var signingPublicKey: Data {
        (try? signingKey().publicKey.compressedRepresentation) ?? Data()
    }

    /// SEC1 compressed KEM public key (33 bytes).
    public var kemPublicKey: Data {
        (try? kemKey().publicKey.compressedRepresentation) ?? Data()
    }
}
