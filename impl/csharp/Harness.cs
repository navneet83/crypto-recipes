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

void Replay(string name, Recipe r)
{
    var vdir = Path.Combine(root, "vectors", name);
    var cases = JsonSerializer.Deserialize<CaseFile>(File.ReadAllText(Path.Combine(vdir, "cases.json")), json)!.cases;
    foreach (var c in cases)
    {
        string produced = r.Replay(c);
        if (produced != c["output_base64"]) throw new Exception($"{name} case {c["id"]}: produced {produced}");
        if (r.Open(c, "output_base64") != c["plaintext"]) throw new Exception($"{name} case {c["id"]}: decrypt mismatch");
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
            if (r.Consume(it) != it["plaintext"]) throw new Exception($"csharp could not open a {name} record from {batch.producer}");
        Console.WriteLine($"csharp: opened {batch.items.Count} {name} records from {batch.producer}");
    }
    else throw new Exception("usage: harness [<recipe> --emit N FILE | <recipe> --consume FILE]");
}

record Recipe(Func<Dictionary<string, string>, string> Replay, Func<Dictionary<string, string>, string, string> Open,
              Func<int, Dictionary<string, string>> Emit, Func<Dictionary<string, string>, string> Consume);
record CaseFile(List<Dictionary<string, string>> cases);
record Batch(string recipe, string producer, List<Dictionary<string, string>> items);
