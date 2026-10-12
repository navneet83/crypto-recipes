// Recipe pbe-record-pbkdf2-gcm-v1: encrypt a short record with a password.
// CryptoKit for AES-GCM (iOS 13+, macOS 10.15+) and CommonCrypto for PBKDF2; nothing else.
//
// Key:    PBKDF2-HMAC-SHA256, 600000 iterations, random 16-byte salt, over the UTF-8 bytes of the password.
// Cipher: AES-256-GCM, random 12-byte nonce, 16-byte tag, no additional data.
// Output: Base64 of  version (1 byte, 0x01) || salt (16) || nonce (12) || ciphertext || tag (16).
// This is the fallback profile of recipe R1; see RECIPES.md for the Argon2id and XAES-256-GCM profiles.
// Run the harness as a script: swift pbe_record_pbkdf2_gcm_v1.swift [--emit N FILE | --consume FILE]

import CommonCrypto
import CryptoKit
import Foundation

let recipe = "pbe-record-pbkdf2-gcm-v1"
let version: UInt8 = 0x01
let iterations: UInt32 = 600_000
let saltBytes = 16
let nonceBytes = 12
let tagBytes = 16

enum RecipeError: Error { case badInput, kdfFailed, notARecord }

func deriveKey(password: String, salt: Data) throws -> SymmetricKey {
    var key = [UInt8](repeating: 0, count: 32)
    let status = salt.withUnsafeBytes { saltPtr in
        CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), password, password.utf8.count,
                             saltPtr.bindMemory(to: UInt8.self).baseAddress, salt.count,
                             CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), iterations, &key, key.count)
    }
    guard status == kCCSuccess else { throw RecipeError.kdfFailed }
    return SymmetricKey(data: key)
}

func randomData(_ count: Int) -> Data {
    var bytes = [UInt8](repeating: 0, count: count)
    _ = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
    return Data(bytes)
}

func encrypt(password: String, plaintext: String, salt: Data? = nil, nonce: Data? = nil) throws -> String {
    let salt = salt ?? randomData(saltBytes)
    let nonce = nonce ?? randomData(nonceBytes)
    guard salt.count == saltBytes, nonce.count == nonceBytes else { throw RecipeError.badInput }
    let key = try deriveKey(password: password, salt: salt)
    let box = try AES.GCM.seal(Data(plaintext.utf8), using: key, nonce: AES.GCM.Nonce(data: nonce))
    // `combined` is nonce || ciphertext || tag.
    return (Data([version]) + salt + box.combined!).base64EncodedString()
}

func decrypt(password: String, text: String) throws -> String {
    guard let data = Data(base64Encoded: text), data.count >= 1 + saltBytes + nonceBytes + tagBytes, data[data.startIndex] == version else { throw RecipeError.notARecord }
    let salt = data.dropFirst(1).prefix(saltBytes)
    let key = try deriveKey(password: password, salt: salt)
    // A wrong password or any modification throws here; there is never partial output.
    let opened = try AES.GCM.open(AES.GCM.SealedBox(combined: data.dropFirst(1 + saltBytes)), using: key)
    guard let s = String(data: opened, encoding: .utf8) else { throw RecipeError.badInput }
    return s
}

// Harness.
func hex(_ s: String) -> Data {
    var out = Data(); var i = s.startIndex
    while i < s.endIndex { let j = s.index(i, offsetBy: 2); out.append(UInt8(s[i..<j], radix: 16)!); i = j }
    return out
}
struct Case: Decodable { let id: String; let password, salt_hex, nonce_hex, plaintext, output_base64: String }
struct Cases: Decodable { let cases: [Case] }
struct Negative: Decodable { let id, password, input_base64, note: String }
struct Negatives: Decodable { let cases: [Negative] }
struct Item: Codable { let password, plaintext, record: String }
struct Batch: Codable { let recipe, producer: String; let items: [Item] }

let here = URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent()
let vdir = here.appendingPathComponent("../../vectors/\(recipe)")
let args = Array(CommandLine.arguments.dropFirst())
if args.first == "--emit" {
    let n = Int(args[1])!
    var items: [Item] = []
    for i in 0..<n {
        let password = "pw-\(i)-\(UUID().uuidString)"
        let plaintext = i % 3 == 0 ? "" : "record \(i) \(String(repeating: "x", count: i * 7)) ünïcödé ✓"
        items.append(Item(password: password, plaintext: plaintext, record: try encrypt(password: password, plaintext: plaintext)))
    }
    try JSONEncoder().encode(Batch(recipe: recipe, producer: "swift", items: items)).write(to: URL(fileURLWithPath: args[2]))
    print("swift: emitted \(n) records to \(args[2])")
} else if args.first == "--consume" {
    let batch = try JSONDecoder().decode(Batch.self, from: Data(contentsOf: URL(fileURLWithPath: args[1])))
    precondition(batch.recipe == recipe, "recipe mismatch")
    for it in batch.items { let opened = try decrypt(password: it.password, text: it.record); precondition(opened == it.plaintext, "swift could not open a record from \(batch.producer)") }
    print("swift: opened \(batch.items.count) records from \(batch.producer)")
} else {
    let cases = try JSONDecoder().decode(Cases.self, from: Data(contentsOf: vdir.appendingPathComponent("cases.json"))).cases
    for c in cases {
        let produced = try encrypt(password: c.password, plaintext: c.plaintext, salt: hex(c.salt_hex), nonce: hex(c.nonce_hex))
        precondition(produced == c.output_base64, "case \(c.id): produced \(produced)")
        let opened = try decrypt(password: c.password, text: c.output_base64)
        precondition(opened == c.plaintext, "case \(c.id): decrypt mismatch")
    }
    let negatives = try JSONDecoder().decode(Negatives.self, from: Data(contentsOf: vdir.appendingPathComponent("negative.json"))).cases
    for c in negatives {
        if let opened = try? decrypt(password: c.password, text: c.input_base64) { preconditionFailure("negative case \(c.id) (\(c.note)) returned plaintext: \(opened)") }
    }
    print("swift: \(cases.count) cases and \(negatives.count) negative cases OK for \(recipe)")
}
