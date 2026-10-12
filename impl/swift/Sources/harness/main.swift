// Runs the recipes over their vectors, emits random records, or consumes another implementation's records.
//   swift run harness                            replay cases.json and negative.json for every recipe
//   swift run harness --list                     print the recipes this implementation supports, one per line
//   swift run harness <recipe> --emit N FILE     write N random records for the cross-language check
//   swift run harness <recipe> --consume FILE    open records produced by another implementation
// RECIPES_ROOT points at the checkout (default: two directories up from the package).
import Foundation
import Recipes

struct Recipe {
    let replay: ([String: String]) throws -> String
    let open: ([String: String], String) throws -> String
    let emit: (Int) throws -> [String: String]
    let consume: ([String: String]) throws -> String
    /// CryptoKit's Ed25519 signing is randomized, so its output cannot equal the vector; it is verified instead.
    var deterministic = true
}

func hex(_ s: String) -> Data {
    var out = Data(); var i = s.startIndex
    while i < s.endIndex { let j = s.index(i, offsetBy: 2); out.append(UInt8(s[i..<j], radix: 16)!); i = j }
    return out
}
func toHex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }
func plaintextFor(_ i: Int) -> String { i % 3 == 0 ? "" : "record \(i) \(String(repeating: "x", count: i * 7)) ünïcödé ✓" }
func randomBytes(_ n: Int) -> Data { Data((0..<n).map { _ in UInt8.random(in: 0...255) }) }

let recipes: [(String, Recipe)] = [
    (PbeRecordPbkdf2GcmV1.recipe, Recipe(
        replay: { c in try PbeRecordPbkdf2GcmV1.encrypt(password: c["password"]!, plaintext: c["plaintext"]!, salt: hex(c["salt_hex"]!), nonce: hex(c["nonce_hex"]!)) },
        open: { c, f in try PbeRecordPbkdf2GcmV1.decrypt(password: c["password"]!, text: c[f]!) },
        emit: { i in let pw = "pw-\(i)-\(UUID().uuidString)"; return ["password": pw, "plaintext": plaintextFor(i), "record": try PbeRecordPbkdf2GcmV1.encrypt(password: pw, plaintext: plaintextFor(i))] },
        consume: { it in try PbeRecordPbkdf2GcmV1.decrypt(password: it["password"]!, text: it["record"]!) })),
    (AeadRecordV1.recipe, Recipe(
        replay: { c in try AeadRecordV1.encrypt(key: hex(c["key_hex"]!), plaintext: c["plaintext"]!, aad: c["aad"]!, nonce: hex(c["nonce_hex"]!)) },
        open: { c, f in try AeadRecordV1.decrypt(key: hex(c["key_hex"]!), text: c[f]!, aad: c["aad"]!) },
        emit: { i in let key = randomBytes(32); let aad = i % 2 == 0 ? "aad-\(i)" : ""; return ["key_hex": toHex(key), "aad": aad, "plaintext": plaintextFor(i), "record": try AeadRecordV1.encrypt(key: key, plaintext: plaintextFor(i), aad: aad)] },
        consume: { it in try AeadRecordV1.decrypt(key: hex(it["key_hex"]!), text: it["record"]!, aad: it["aad"]!) })),
    (SignDetachedV1.recipe, signatureRecipe(publicKey: SignDetachedV1.publicKey, sign: SignDetachedV1.sign, verify: SignDetachedV1.verify, deterministic: false)),
] + pqRecipes()

/// CryptoKit randomizes Ed25519 signing, and ML-DSA signing is randomized by definition, so neither output can equal
/// the vector; the harness verifies their own output instead.
func signatureRecipe(publicKey: @escaping (Data) throws -> Data, sign: @escaping (Data, String) throws -> String,
                     verify: @escaping (Data, String, String) throws -> Void, deterministic: Bool) -> Recipe {
    Recipe(
        replay: { c in
            guard toHex(try publicKey(hex(c["seed_hex"]!))) == c["public_hex"] else { fatalError("\(c["id"]!): public key mismatch") }
            return try sign(hex(c["seed_hex"]!), c["message"]!) },
        open: { c, f in try verify(hex(c["public_hex"]!), c["message"]!, c[f]!); return c["message"]! },
        emit: { i in let seed = randomBytes(32); return ["seed_hex": toHex(seed), "public_hex": toHex(try publicKey(seed)), "message": plaintextFor(i), "record": try sign(seed, plaintextFor(i))] },
        consume: { it in
            guard toHex(try publicKey(hex(it["seed_hex"]!))) == it["public_hex"] else { fatalError("public key mismatch") }
            try verify(hex(it["public_hex"]!), it["message"]!, it["record"]!); return it["message"]! },
        deterministic: deterministic)
}

func pqRecipes() -> [(String, Recipe)] {
    if #available(macOS 26.0, iOS 26.0, *) {
        return [(SignDetachedPqV1.recipe, signatureRecipe(publicKey: SignDetachedPqV1.publicKey, sign: SignDetachedPqV1.sign, verify: SignDetachedPqV1.verify, deterministic: false))]
    }
    return []
}

/// Encryption vectors carry the plaintext, signature vectors the message.
func expected(_ c: [String: String]) -> String { c["message"] ?? c["plaintext"]! }

struct CaseFile: Decodable { let cases: [[String: String]] }
struct Batch: Codable { let recipe, producer: String; let items: [[String: String]] }

let root = ProcessInfo.processInfo.environment["RECIPES_ROOT"].map { URL(fileURLWithPath: $0) }
    ?? URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("../../../..").standardized
func replay(_ name: String, _ r: Recipe) throws {
    let vdir = root.appendingPathComponent("vectors/\(name)")
    let cases = try JSONDecoder().decode(CaseFile.self, from: Data(contentsOf: vdir.appendingPathComponent("cases.json"))).cases
    for c in cases {
        let produced = try r.replay(c)
        let field = c["signature_base64"] != nil ? "signature_base64" : "output_base64"
        if r.deterministic {
            guard produced == c[field] else { fatalError("\(name) case \(c["id"]!): produced \(produced)") }
        } else {
            var own = c; own[field] = produced
            guard try r.open(own, field) == expected(c) else { fatalError("\(name) case \(c["id"]!): own output does not verify") }
        }
        guard try r.open(c, field) == expected(c) else { fatalError("\(name) case \(c["id"]!): open mismatch") }
    }
    let negative = try JSONDecoder().decode(CaseFile.self, from: Data(contentsOf: vdir.appendingPathComponent("negative.json"))).cases
    for c in negative {
        if let opened = try? r.open(c, "input_base64") { fatalError("\(name) negative case \(c["id"]!) (\(c["note"]!)) returned plaintext: \(opened)") }
    }
    print("swift: \(cases.count) cases and \(negative.count) negative cases OK for \(name)")
}

let args = Array(CommandLine.arguments.dropFirst())
if args == ["--list"] {
    print(recipes.map { $0.0 }.joined(separator: "\n"))
} else if args.isEmpty {
    for (name, r) in recipes { try replay(name, r) }
} else {
    let name = args[0]
    guard let r = recipes.first(where: { $0.0 == name })?.1 else { fatalError("unknown recipe \(name)") }
    if args.count == 4, args[1] == "--emit" {
        let n = Int(args[2])!
        let items = try (0..<n).map(r.emit)
        try JSONEncoder().encode(Batch(recipe: name, producer: "swift", items: items)).write(to: URL(fileURLWithPath: args[3]))
        print("swift: emitted \(n) records to \(args[3]) for \(name)")
    } else if args.count == 3, args[1] == "--consume" {
        let batch = try JSONDecoder().decode(Batch.self, from: Data(contentsOf: URL(fileURLWithPath: args[2])))
        guard batch.recipe == name else { fatalError("recipe mismatch") }
        for it in batch.items { guard try r.consume(it) == expected(it) else { fatalError("swift could not open a \(name) record from \(batch.producer)") } }
        print("swift: opened \(batch.items.count) \(name) records from \(batch.producer)")
    } else {
        fatalError("usage: harness [<recipe> --emit N FILE | <recipe> --consume FILE]")
    }
}
