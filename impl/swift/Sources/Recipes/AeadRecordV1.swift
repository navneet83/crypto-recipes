// Recipe aead-record-v1: encrypt a short record with a 32-byte key you already have.
// CryptoKit for AES-GCM and CommonCrypto for the single AES block operation CryptoKit does not expose.
// Cipher is XAES-256-GCM (https://c2sp.org/XAES-256-GCM): a 24-byte random nonce, from which a per-message
// AES-256-GCM key is derived with one block of AES-CMAC, so random nonces are safe for any number of messages under one key.
//
// Key:    32 bytes, from a KMS, a key store or a KDF; never a password (see pbe-record-v1).
// Cipher: XAES-256-GCM, random 24-byte nonce, 16-byte tag, optional additional data (not stored).
// Output: Base64 of  version (1 byte, 0x01) || nonce (24) || ciphertext || tag (16).

import CommonCrypto
import CryptoKit
import Foundation

public enum AeadRecordV1 {
    public static let recipe = "aead-record-v1"
    static let version: UInt8 = 0x01
    static let keyBytes = 32
    static let nonceBytes = 24
    static let tagBytes = 16

    public enum Error: Swift.Error { case badInput, blockFailed, notARecord }

    static func aesBlock(key: Data, block: [UInt8]) throws -> [UInt8] {
        var out = [UInt8](repeating: 0, count: 16)
        var moved = 0
        let status = key.withUnsafeBytes { keyPtr in
            CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionECBMode),
                    keyPtr.baseAddress, key.count, nil, block, 16, &out, 16, &moved)
        }
        guard status == kCCSuccess, moved == 16 else { throw Error.blockFailed }
        return out
    }

    /// Steps 1-5 of the XAES-256-GCM key derivation: the per-message AES-256-GCM key. The GCM nonce is nonce[12..<24].
    static func xaesSubkey(key: Data, nonce: Data) throws -> SymmetricKey {
        let l = try aesBlock(key: key, block: [UInt8](repeating: 0, count: 16))
        var k1 = [UInt8](repeating: 0, count: 16)
        for i in 0..<16 { k1[i] = (l[i] << 1) | (i < 15 ? l[i + 1] >> 7 : 0) }
        if l[0] & 0x80 != 0 { k1[15] ^= 0x87 }
        var kx = [UInt8]()
        for counter: UInt8 in [1, 2] {
            var m = [0x00, counter, 0x58, 0x00] + [UInt8](nonce.prefix(12))
            for i in 0..<16 { m[i] ^= k1[i] }
            kx += try aesBlock(key: key, block: m)
        }
        return SymmetricKey(data: kx)
    }

    /// nonce is nil in normal use and generated here; the harness passes a fixed value to reproduce the vectors.
    public static func encrypt(key: Data, plaintext: String, aad: String = "", nonce: Data? = nil) throws -> String {
        guard key.count == keyBytes else { throw Error.badInput }
        let nonce = nonce ?? randomData(nonceBytes)
        guard nonce.count == nonceBytes else { throw Error.badInput }
        let box = try AES.GCM.seal(Data(plaintext.utf8), using: try xaesSubkey(key: key, nonce: nonce),
                                   nonce: AES.GCM.Nonce(data: nonce.suffix(12)), authenticating: Data(aad.utf8))
        return (Data([version]) + nonce + box.ciphertext + box.tag).base64EncodedString()
    }

    /// A wrong key, wrong additional data or any modification throws; there is never partial output.
    public static func decrypt(key: Data, text: String, aad: String = "") throws -> String {
        guard key.count == keyBytes else { throw Error.badInput }
        guard let data = Data(base64Encoded: text), data.count >= 1 + nonceBytes + tagBytes, data[data.startIndex] == version else { throw Error.notARecord }
        let nonce = Data(data.dropFirst(1).prefix(nonceBytes))
        let sealed = data.dropFirst(1 + nonceBytes)
        let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: nonce.suffix(12)), ciphertext: sealed.dropLast(tagBytes), tag: sealed.suffix(tagBytes))
        let opened = try AES.GCM.open(box, using: try xaesSubkey(key: key, nonce: nonce), authenticating: Data(aad.utf8))
        guard let s = String(data: opened, encoding: .utf8) else { throw Error.badInput }
        return s
    }
}
