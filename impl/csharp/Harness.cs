// Runs the recipe over its vectors, emits random records, or consumes another implementation's records.
using System.Text.Json;
using System.Text.Json.Serialization;
using CryptoRecipes;

var root = Environment.GetEnvironmentVariable("RECIPES_ROOT") ?? ".";
var vdir = Path.Combine(root, "vectors", PbeRecordPbkdf2GcmV1.Recipe);
var json = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower, WriteIndented = true,
    Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

if (args.Length == 3 && args[0] == "--emit")
{
    int n = int.Parse(args[1]);
    var items = new List<Item>();
    for (int i = 0; i < n; i++)
    {
        string password = $"pw-{i}-{Guid.NewGuid()}";
        string plaintext = i % 3 == 0 ? "" : $"record {i} {new string('x', i * 7)} ünïcödé ✓";
        items.Add(new Item(password, plaintext, PbeRecordPbkdf2GcmV1.Encrypt(password, plaintext)));
    }
    File.WriteAllText(args[2], JsonSerializer.Serialize(new Batch(PbeRecordPbkdf2GcmV1.Recipe, "csharp", items), json));
    Console.WriteLine($"csharp: emitted {n} records to {args[2]}");
}
else if (args.Length == 2 && args[0] == "--consume")
{
    var batch = JsonSerializer.Deserialize<Batch>(File.ReadAllText(args[1]), json)!;
    if (batch.Recipe != PbeRecordPbkdf2GcmV1.Recipe) throw new Exception("recipe mismatch");
    foreach (var it in batch.Items)
        if (PbeRecordPbkdf2GcmV1.Decrypt(it.Password, it.Record) != it.Plaintext)
            throw new Exception($"csharp could not open a record from {batch.Producer}");
    Console.WriteLine($"csharp: opened {batch.Items.Count} records from {batch.Producer}");
}
else
{
    var cases = JsonSerializer.Deserialize<CaseFile>(File.ReadAllText(Path.Combine(vdir, "cases.json")), json)!.Cases;
    foreach (var c in cases)
    {
        string produced = PbeRecordPbkdf2GcmV1.Encrypt(c.Password, c.Plaintext, Convert.FromHexString(c.SaltHex), Convert.FromHexString(c.NonceHex));
        if (produced != c.OutputBase64) throw new Exception($"case {c.Id}: produced {produced}");
        if (PbeRecordPbkdf2GcmV1.Decrypt(c.Password, c.OutputBase64) != c.Plaintext) throw new Exception($"case {c.Id}: decrypt mismatch");
    }
    var negative = JsonSerializer.Deserialize<NegativeFile>(File.ReadAllText(Path.Combine(vdir, "negative.json")), json)!.Cases;
    foreach (var c in negative)
    {
        string opened;
        try { opened = PbeRecordPbkdf2GcmV1.Decrypt(c.Password, c.InputBase64); } catch { continue; }
        throw new Exception($"negative case {c.Id} ({c.Note}) returned plaintext: {opened}");
    }
    Console.WriteLine($"csharp: {cases.Count} cases and {negative.Count} negative cases OK for {PbeRecordPbkdf2GcmV1.Recipe}");
}

record Case(string Id, string Password, string SaltHex, string NonceHex, string Plaintext, string OutputBase64);
record CaseFile(List<Case> Cases);
record Negative(string Id, string Password, string InputBase64, string Note);
record NegativeFile(List<Negative> Cases);
record Item(string Password, string Plaintext, string Record);
record Batch(string Recipe, string Producer, List<Item> Items);
