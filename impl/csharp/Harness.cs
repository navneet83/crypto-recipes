// Runs the recipes over their vectors, emits random records, or consumes another implementation's records.
//   harness                            replay cases.json and negative.json for every recipe
//   harness --list                     print the recipes this implementation supports, one per line
//   harness <recipe> --emit N FILE     write N random records for the cross-language check
//   harness <recipe> --consume FILE    open records produced by another implementation
// RECIPES_ROOT points at the checkout (default: current directory).
using System.Security.Cryptography;
using System.Text.Json;
using CryptoRecipes;

var root = Environment.GetEnvironmentVariable("RECIPES_ROOT") ?? ".";
var json = new JsonSerializerOptions { WriteIndented = true, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping };
// Encryption vectors carry the plaintext, signature vectors the message.
string Expected(Dictionary<string, string> c) => c.TryGetValue("message", out var m) ? m : c["plaintext"];
string PlaintextFor(int i) => i % 3 == 0 ? "" : $"record {i} {new string('x', i * 7)} ünïcödé ✓";

var recipes = new Dictionary<string, Recipe>
{
    [PbeRecordPbkdf2GcmV1.Recipe] = new(
        c => PbeRecordPbkdf2GcmV1.Encrypt(c["password"], c["plaintext"], Convert.FromHexString(c["salt_hex"]), Convert.FromHexString(c["nonce_hex"])),
        (c, f) => PbeRecordPbkdf2GcmV1.Decrypt(c["password"], c[f]),
        i => { var pw = $"pw-{i}-{Guid.NewGuid()}"; return new() { ["password"] = pw, ["plaintext"] = PlaintextFor(i), ["record"] = PbeRecordPbkdf2GcmV1.Encrypt(pw, PlaintextFor(i)) }; },
        it => PbeRecordPbkdf2GcmV1.Decrypt(it["password"], it["record"])),
    [AeadRecordV1.Recipe] = new(
        c => AeadRecordV1.Encrypt(Convert.FromHexString(c["key_hex"]), c["plaintext"], c["aad"], Convert.FromHexString(c["nonce_hex"])),
        (c, f) => AeadRecordV1.Decrypt(Convert.FromHexString(c["key_hex"]), c[f], c["aad"]),
        i => { var key = RandomNumberGenerator.GetBytes(32); var aad = i % 2 == 0 ? $"aad-{i}" : ""; return new() { ["key_hex"] = Convert.ToHexString(key).ToLowerInvariant(), ["aad"] = aad, ["plaintext"] = PlaintextFor(i), ["record"] = AeadRecordV1.Encrypt(key, PlaintextFor(i), aad) }; },
        it => AeadRecordV1.Decrypt(Convert.FromHexString(it["key_hex"]), it["record"], it["aad"])),
};
if (SignDetachedPqV1.Available)
    recipes[SignDetachedPqV1.Recipe] = new(
        c => { if (Convert.ToHexString(SignDetachedPqV1.PublicKey(Convert.FromHexString(c["seed_hex"]))).ToLowerInvariant() != c["public_hex"]) throw new Exception($"{c["id"]}: public key mismatch"); return SignDetachedPqV1.Sign(Convert.FromHexString(c["seed_hex"]), c["message"]); },
        (c, f) => { SignDetachedPqV1.Verify(Convert.FromHexString(c["public_hex"]), c["message"], c[f]); return c["message"]; },
        i => { var seed = RandomNumberGenerator.GetBytes(32); return new() { ["seed_hex"] = Convert.ToHexString(seed).ToLowerInvariant(), ["public_hex"] = Convert.ToHexString(SignDetachedPqV1.PublicKey(seed)).ToLowerInvariant(), ["message"] = PlaintextFor(i), ["record"] = SignDetachedPqV1.Sign(seed, PlaintextFor(i)) }; },
        it => { if (Convert.ToHexString(SignDetachedPqV1.PublicKey(Convert.FromHexString(it["seed_hex"]))).ToLowerInvariant() != it["public_hex"]) throw new Exception("public key mismatch"); SignDetachedPqV1.Verify(Convert.FromHexString(it["public_hex"]), it["message"], it["record"]); return it["message"]; },
        Deterministic: false);

void Replay(string name, Recipe r)
{
    var vdir = Path.Combine(root, "vectors", name);
    var cases = JsonSerializer.Deserialize<CaseFile>(File.ReadAllText(Path.Combine(vdir, "cases.json")), json)!.cases;
    foreach (var c in cases)
    {
        string produced = r.Replay(c);
        string field = c.ContainsKey("signature_base64") ? "signature_base64" : "output_base64";
        if (!r.Deterministic)
        {
            var own = new Dictionary<string, string>(c) { [field] = produced };
            if (r.Open(own, field) != Expected(c)) throw new Exception($"{name} case {c["id"]}: own output does not verify");
        }
        else if (produced != c[field]) throw new Exception($"{name} case {c["id"]}: produced {produced}");
        if (r.Open(c, field) != Expected(c)) throw new Exception($"{name} case {c["id"]}: open mismatch");
    }
    var negative = JsonSerializer.Deserialize<CaseFile>(File.ReadAllText(Path.Combine(vdir, "negative.json")), json)!.cases;
    foreach (var c in negative)
    {
        string opened;
        try { opened = r.Open(c, "input_base64"); } catch { continue; }
        throw new Exception($"{name} negative case {c["id"]} ({c["note"]}) returned plaintext: {opened}");
    }
    Console.WriteLine($"csharp: {cases.Count} cases and {negative.Count} negative cases OK for {name}");
}

if (args.Length == 1 && args[0] == "--list")
{
    Console.WriteLine(string.Join("\n", recipes.Keys));
}
else if (args.Length == 0)
{
    foreach (var (name, r) in recipes) Replay(name, r);
}
else
{
    var name = args[0];
    if (!recipes.TryGetValue(name, out var r)) throw new Exception($"unknown recipe {name}");
    if (args.Length == 4 && args[1] == "--emit")
    {
        int n = int.Parse(args[2]);
        var items = Enumerable.Range(0, n).Select(r.Emit).ToList();
        File.WriteAllText(args[3], JsonSerializer.Serialize(new Batch(name, "csharp", items), json));
        Console.WriteLine($"csharp: emitted {n} records to {args[3]} for {name}");
    }
    else if (args.Length == 3 && args[1] == "--consume")
    {
        var batch = JsonSerializer.Deserialize<Batch>(File.ReadAllText(args[2]), json)!;
        if (batch.recipe != name) throw new Exception("recipe mismatch");
        foreach (var it in batch.items)
            if (r.Consume(it) != Expected(it)) throw new Exception($"csharp could not open a {name} record from {batch.producer}");
        Console.WriteLine($"csharp: opened {batch.items.Count} {name} records from {batch.producer}");
    }
    else throw new Exception("usage: harness [<recipe> --emit N FILE | <recipe> --consume FILE]");
}

// Deterministic is false for a signature scheme whose output cannot equal the vector; own output is verified instead.
record Recipe(Func<Dictionary<string, string>, string> Replay, Func<Dictionary<string, string>, string, string> Open,
              Func<int, Dictionary<string, string>> Emit, Func<Dictionary<string, string>, string> Consume, bool Deterministic = true);
record CaseFile(List<Dictionary<string, string>> cases);
record Batch(string recipe, string producer, List<Dictionary<string, string>> items);
