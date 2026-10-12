// Recipe pbe-record-pbkdf2-gcm-v1: encrypt a short record with a password.
// CryptoKit for AES-GCM (iOS 13+, macOS 10.15+) and CommonCrypto for PBKDF2; nothing else.
//
// Key:    PBKDF2-HMAC-SHA256, 600000 iterations, random 16-byte salt, over the UTF-8 bytes of the password.
// Cipher: AES-256-GCM, random 12-byte nonce, 16-byte tag, no additional data.
// Output: Base64 of  version (1 byte, 0x01) || salt (16) || nonce (12) || ciphertext || tag (16).
// This is the fallback profile of recipe R1; see RECIPES.md for the Argon2id and XAES-256-GCM profiles.

import CommonCrypto
import CryptoKit
import Foundation

public enum PbeRecordPbkdf2GcmV1 {
    public static let recipe = "pbe-record-pbkdf2-gcm-v1"
    static let version: UInt8 = 0x01
    static let iterations: UInt32 = 600_000
    static let saltBytes = 16
    static let nonceBytes = 12
    static let tagBytes = 16

    public enum Error: Swift.Error { case badInput, kdfFailed, notARecord }

    static func deriveKey(password: String, salt: Data) throws -> SymmetricKey {
        var key = [UInt8](repeating: 0, count: 32)
        let status = salt.withUnsafeBytes { saltPtr in
            CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), password, password.utf8.count,
                                 saltPtr.bindMemory(to: UInt8.self).baseAddress, salt.count,
                                 CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), iterations, &key, key.count)
        }
        guard status == kCCSuccess else { throw Error.kdfFailed }
        return SymmetricKey(data: key)
    }

    /// salt and nonce are nil in normal use and generated here; the harness passes fixed values to reproduce the vectors.
    public static func encrypt(password: String, plaintext: String, salt: Data? = nil, nonce: Data? = nil) throws -> String {
        let salt = salt ?? randomData(saltBytes)
        let nonce = nonce ?? randomData(nonceBytes)
        guard salt.count == saltBytes, nonce.count == nonceBytes else { throw Error.badInput }
        let key = try deriveKey(password: password, salt: salt)
        let box = try AES.GCM.seal(Data(plaintext.utf8), using: key, nonce: AES.GCM.Nonce(data: nonce))
        // `combined` is nonce || ciphertext || tag.
        return (Data([version]) + salt + box.combined!).base64EncodedString()
    }

    /// A wrong password or any modification throws; there is never partial output.
    public static func decrypt(password: String, text: String) throws -> String {
        guard let data = Data(base64Encoded: text), data.count >= 1 + saltBytes + nonceBytes + tagBytes, data[data.startIndex] == version else { throw Error.notARecord }
        let salt = data.dropFirst(1).prefix(saltBytes)
        let key = try deriveKey(password: password, salt: salt)
        let opened = try AES.GCM.open(AES.GCM.SealedBox(combined: data.dropFirst(1 + saltBytes)), using: key)
        guard let s = String(data: opened, encoding: .utf8) else { throw Error.badInput }
        return s
    }
}

func randomData(_ count: Int) -> Data {
    var bytes = [UInt8](repeating: 0, count: count)
    _ = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
    return Data(bytes)
}
