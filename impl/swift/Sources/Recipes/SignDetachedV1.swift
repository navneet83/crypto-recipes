// Recipe sign-detached-v1: sign a message and verify the signature.
// CryptoKit only (iOS 13+, macOS 10.15+).
//
// Keys:      Ed25519 (RFC 8032). Private key is the 32-byte seed (CryptoKit's rawRepresentation), public key is the
//            32-byte point, both Base64 when transported.
// Input:     "crypto-recipes/sign-detached-v1" || 0x00 || message. The prefix stops a signature made for this recipe
//            from meaning anything in another protocol that signs raw bytes with the same key, and the other way round.
// Signature: the 64 raw Ed25519 bytes, Base64 (standard alphabet, with padding). The public key and the message
//            travel separately, which is what "detached" means.

import CryptoKit
import Foundation

public enum SignDetachedV1 {
    public static let recipe = "sign-detached-v1"
    static let domain = Data("crypto-recipes/sign-detached-v1\0".utf8)
    static let seedBytes = 32, publicBytes = 32, signatureBytes = 64

    public enum Error: Swift.Error { case badInput, invalidSignature }

    static func input(_ message: String) -> Data { domain + Data(message.utf8) }

    public static func publicKey(seed: Data) throws -> Data {
        guard seed.count == seedBytes else { throw Error.badInput }
        return try Curve25519.Signing.PrivateKey(rawRepresentation: seed).publicKey.rawRepresentation
    }

    public static func sign(seed: Data, message: String) throws -> String {
        guard seed.count == seedBytes else { throw Error.badInput }
        return try Curve25519.Signing.PrivateKey(rawRepresentation: seed).signature(for: input(message)).base64EncodedString()
    }

    /// Returns normally for a valid signature and throws for anything else; callers never get a boolean to ignore.
    public static func verify(publicKey: Data, message: String, signature: String) throws {
        guard publicKey.count == publicBytes, let sig = Data(base64Encoded: signature), sig.count == signatureBytes else { throw Error.invalidSignature }
        guard try Curve25519.Signing.PublicKey(rawRepresentation: publicKey).isValidSignature(sig, for: input(message)) else { throw Error.invalidSignature }
    }
}
