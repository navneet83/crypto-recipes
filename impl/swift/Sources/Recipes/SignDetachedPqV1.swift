// Recipe sign-detached-pq-v1: sign a message and verify the signature, post-quantum.
// CryptoKit only (iOS 26+, macOS 26+).
//
// Keys:      ML-DSA-65 (FIPS 204). Private key is the 32-byte seed (CryptoKit's seedRepresentation); public key is the
//            1952-byte encoding (rawRepresentation). Both Base64 when transported.
// Input:     "crypto-recipes/sign-detached-pq-v1" || 0x00 || message, with an empty FIPS 204 context string.
// Signature: the 3309 raw ML-DSA-65 bytes, Base64. Signing is randomized: two signatures of one message differ.

import CryptoKit
import Foundation

@available(macOS 26.0, iOS 26.0, *)
public enum SignDetachedPqV1 {
    public static let recipe = "sign-detached-pq-v1"
    static let domain = Data("crypto-recipes/sign-detached-pq-v1\0".utf8)
    static let seedBytes = 32, publicBytes = 1952, signatureBytes = 3309

    public enum Error: Swift.Error { case badInput, invalidSignature }

    static func input(_ message: String) -> Data { domain + Data(message.utf8) }

    public static func publicKey(seed: Data) throws -> Data {
        guard seed.count == seedBytes else { throw Error.badInput }
        return try MLDSA65.PrivateKey(seedRepresentation: seed, publicKey: nil).publicKey.rawRepresentation
    }

    public static func sign(seed: Data, message: String) throws -> String {
        guard seed.count == seedBytes else { throw Error.badInput }
        return try MLDSA65.PrivateKey(seedRepresentation: seed, publicKey: nil).signature(for: input(message)).base64EncodedString()
    }

    /// Returns normally for a valid signature and throws for anything else; callers never get a boolean to ignore.
    public static func verify(publicKey: Data, message: String, signature: String) throws {
        guard publicKey.count == publicBytes, let sig = Data(base64Encoded: signature), sig.count == signatureBytes else { throw Error.invalidSignature }
        guard try MLDSA65.PublicKey(rawRepresentation: publicKey).isValidSignature(sig, for: input(message)) else { throw Error.invalidSignature }
    }
}
