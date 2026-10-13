// Recipe hpke-envelope-pq-v1: encrypt a short record to a recipient's public key, post-quantum hybrid.
// CryptoKit only (iOS 26+, macOS 26+).
//
// Suite:  HPKE base mode with the KEM MLKEM768-X25519 (X-Wing, KEM id 0x647a, draft-ietf-hpke-pq), HKDF-SHA256,
//         AES-256-GCM, single-shot, no additional data. A record stays confidential unless both ML-KEM-768 and X25519 fall.
// Info:   "crypto-recipes/hpke-envelope-pq-v1".
// Keys:   recipient private key is the 32-byte X-Wing seed (seedRepresentation); public key is ML-KEM-768 (1184) || X25519 (32).
// Output: Base64 of  version (1 byte, 0x01) || enc (1120) || ciphertext || tag (16).

import CryptoKit
import Foundation

@available(macOS 26.0, iOS 26.0, *)
public enum HpkeEnvelopePqV1 {
    public static let recipe = "hpke-envelope-pq-v1"
    static let version: UInt8 = 0x01
    static let info = Data("crypto-recipes/hpke-envelope-pq-v1".utf8)
    static let seedBytes = 32, publicBytes = 1216, encBytes = 1120, tagBytes = 16
    static let suite = HPKE.Ciphersuite(kem: .XWingMLKEM768X25519, kdf: .HKDF_SHA256, aead: .AES_GCM_256)

    public enum Error: Swift.Error { case badInput, notARecord }

    static func privateKey(_ seed: Data) throws -> XWingMLKEM768X25519.PrivateKey {
        guard seed.count == seedBytes else { throw Error.badInput }
        return try XWingMLKEM768X25519.PrivateKey(seedRepresentation: seed, publicKey: nil)
    }

    public static func publicKey(privateKey seed: Data) throws -> Data {
        try privateKey(seed).publicKey.rawRepresentation
    }

    public static func encrypt(publicKey: Data, plaintext: String) throws -> String {
        guard publicKey.count == publicBytes else { throw Error.badInput }
        var sender = try HPKE.Sender(recipientKey: XWingMLKEM768X25519.PublicKey(rawRepresentation: publicKey), ciphersuite: suite, info: info)
        let sealed = try sender.seal(Data(plaintext.utf8))
        return (Data([version]) + sender.encapsulatedKey + sealed).base64EncodedString()
    }

    /// A wrong key or any modification throws; there is never partial output.
    public static func decrypt(privateKey seed: Data, text: String) throws -> String {
        guard let data = Data(base64Encoded: text), data.count >= 1 + encBytes + tagBytes, data[data.startIndex] == version else { throw Error.notARecord }
        var recipient = try HPKE.Recipient(privateKey: privateKey(seed), ciphersuite: suite, info: info,
                                           encapsulatedKey: Data(data.dropFirst(1).prefix(encBytes)))
        let opened = try recipient.open(Data(data.dropFirst(1 + encBytes)))
        guard let s = String(data: opened, encoding: .utf8) else { throw Error.badInput }
        return s
    }
}
