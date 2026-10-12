// Recipe hpke-envelope-v1: encrypt a short record to a recipient's public key.
// CryptoKit only (iOS 17+, macOS 14+).
//
// Suite:  HPKE (RFC 9180) base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM, single-shot, no additional data.
//         CryptoKit's ready-made X25519 suite uses ChaCha20-Poly1305, so the suite is spelled out.
// Info:   "crypto-recipes/hpke-envelope-v1", which binds every record to this recipe.
// Keys:   recipient private key is the 32-byte X25519 scalar, public key the 32-byte point.
// Output: Base64 of  version (1 byte, 0x01) || enc (32) || ciphertext || tag (16).

import CryptoKit
import Foundation

@available(macOS 14.0, iOS 17.0, *)
public enum HpkeEnvelopeV1 {
    public static let recipe = "hpke-envelope-v1"
    static let version: UInt8 = 0x01
    static let info = Data("crypto-recipes/hpke-envelope-v1".utf8)
    static let keyBytes = 32, encBytes = 32, tagBytes = 16
    static let suite = HPKE.Ciphersuite(kem: .Curve25519_HKDF_SHA256, kdf: .HKDF_SHA256, aead: .AES_GCM_256)

    public enum Error: Swift.Error { case badInput, notARecord }

    public static func publicKey(privateKey: Data) throws -> Data {
        guard privateKey.count == keyBytes else { throw Error.badInput }
        return try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey).publicKey.rawRepresentation
    }

    public static func encrypt(publicKey: Data, plaintext: String) throws -> String {
        guard publicKey.count == keyBytes else { throw Error.badInput }
        var sender = try HPKE.Sender(recipientKey: Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKey), ciphersuite: suite, info: info)
        let sealed = try sender.seal(Data(plaintext.utf8))  // ciphertext || tag
        return (Data([version]) + sender.encapsulatedKey + sealed).base64EncodedString()
    }

    /// A wrong key or any modification throws; there is never partial output.
    public static func decrypt(privateKey: Data, text: String) throws -> String {
        guard privateKey.count == keyBytes else { throw Error.badInput }
        guard let data = Data(base64Encoded: text), data.count >= 1 + encBytes + tagBytes, data[data.startIndex] == version else { throw Error.notARecord }
        var recipient = try HPKE.Recipient(privateKey: Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey), ciphersuite: suite,
                                           info: info, encapsulatedKey: Data(data.dropFirst(1).prefix(encBytes)))
        let opened = try recipient.open(Data(data.dropFirst(1 + encBytes)))
        guard let s = String(data: opened, encoding: .utf8) else { throw Error.badInput }
        return s
    }
}
