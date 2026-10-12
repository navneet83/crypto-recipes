// Runs the recipes over their vectors, emits random records, or consumes another implementation's records.
// Multi-file source launch (Java 22+): java -Drecipes.root=<checkout> impl/java/Harness.java [<recipe> --emit N FILE | <recipe> --consume FILE]
// A tiny JSON reader keeps this dependency-free; it handles the vector files only.

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public final class Harness {
    interface Recipe {
        String replay(Map<String, String> c) throws Exception;
        String open(Map<String, String> c, String field) throws Exception;
        Map<String, String> emit(int i) throws Exception;
        String consume(Map<String, String> it) throws Exception;
    }

    static final SecureRandom RANDOM = new SecureRandom();
    static final Map<String, Recipe> RECIPES = new LinkedHashMap<>();
    static {
        RECIPES.put(PbeRecordPbkdf2GcmV1.RECIPE, new Recipe() {
            public String replay(Map<String, String> c) throws Exception { return PbeRecordPbkdf2GcmV1.encrypt(c.get("password"), c.get("plaintext"), hex(c.get("salt_hex")), hex(c.get("nonce_hex"))); }
            public String open(Map<String, String> c, String f) throws Exception { return PbeRecordPbkdf2GcmV1.decrypt(c.get("password"), c.get(f)); }
            public Map<String, String> emit(int i) throws Exception {
                String password = "pw-" + i + "-" + UUID.randomUUID();
                return Map.of("password", password, "plaintext", plaintextFor(i), "record", PbeRecordPbkdf2GcmV1.encrypt(password, plaintextFor(i), null, null));
            }
            public String consume(Map<String, String> it) throws Exception { return PbeRecordPbkdf2GcmV1.decrypt(it.get("password"), it.get("record")); }
        });
        RECIPES.put(AeadRecordV1.RECIPE, new Recipe() {
            public String replay(Map<String, String> c) throws Exception { return AeadRecordV1.encrypt(hex(c.get("key_hex")), c.get("plaintext"), c.get("aad"), hex(c.get("nonce_hex"))); }
            public String open(Map<String, String> c, String f) throws Exception { return AeadRecordV1.decrypt(hex(c.get("key_hex")), c.get(f), c.get("aad")); }
            public Map<String, String> emit(int i) throws Exception {
                byte[] key = new byte[32]; RANDOM.nextBytes(key);
                String aad = i % 2 == 0 ? "aad-" + i : "";
                return Map.of("key_hex", toHex(key), "aad", aad, "plaintext", plaintextFor(i), "record", AeadRecordV1.encrypt(key, plaintextFor(i), aad, null));
            }
            public String consume(Map<String, String> it) throws Exception { return AeadRecordV1.decrypt(hex(it.get("key_hex")), it.get("record"), it.get("aad")); }
        });
    }

    static String plaintextFor(int i) { return i % 3 == 0 ? "" : "record " + i + " " + "x".repeat(i * 7) + " ünïcödé ✓"; }

    static byte[] hex(String s) {
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) b[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        return b;
    }

    static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    /** Reads the JSON string literal starting at json[i] == '"'; returns the decoded value and the index after the closing quote. */
    static Map.Entry<String, Integer> readString(String json, int i) {
        StringBuilder b = new StringBuilder();
        for (i++; ; i++) {
            char c = json.charAt(i);
            if (c == '"') return Map.entry(b.toString(), i + 1);
            if (c != '\\') { b.append(c); continue; }
            char n = json.charAt(++i);
            switch (n) {
                case 'n' -> b.append('\n'); case 't' -> b.append('\t'); case 'r' -> b.append('\r');
                case 'b' -> b.append('\b'); case 'f' -> b.append('\f');
                case 'u' -> { b.append((char) Integer.parseInt(json.substring(i + 1, i + 5), 16)); i += 4; }
                default -> b.append(n);
            }
        }
    }

    static String escape(String s) {
        StringBuilder b = new StringBuilder();
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"' -> b.append("\\\""); case '\\' -> b.append("\\\\"); case '\n' -> b.append("\\n");
                case '\r' -> b.append("\\r"); case '\t' -> b.append("\\t");
                default -> { if (c < 0x20) b.append(String.format("\\u%04x", (int) c)); else b.append(c); }
            }
        }
        return b.toString();
    }

    /** Walks the document once: string fields at depth 1 go to top, each depth-2 object's string fields become one map. */
    static List<Map<String, String>> objects(String json, Map<String, String> top) {
        List<Map<String, String>> out = new ArrayList<>();
        Map<String, String> current = null;
        int depth = 0;
        String pendingKey = null;
        for (int i = 0; i < json.length(); ) {
            char c = json.charAt(i);
            if (c == '"') {
                var e = readString(json, i);
                i = e.getValue();
                Map<String, String> target = depth == 1 ? top : depth == 2 ? current : null;
                if (pendingKey == null) pendingKey = e.getKey();
                else { if (target != null) target.put(pendingKey, e.getKey()); pendingKey = null; }
                continue;
            }
            if (c == '{') { if (++depth == 2) current = new HashMap<>(); }
            else if (c == '}') { if (depth-- == 2) out.add(current); }
            else if (c == '[' || c == ']' || c == ',') pendingKey = null;
            i++;
        }
        return out;
    }

    static void replay(String name, Recipe r) throws Exception {
        Path vdir = Path.of(System.getProperty("recipes.root", ".")).resolve("vectors").resolve(name);
        List<Map<String, String>> cases = objects(Files.readString(vdir.resolve("cases.json")), new HashMap<>());
        for (var c : cases) {
            String produced = r.replay(c);
            if (!produced.equals(c.get("output_base64"))) throw new IllegalStateException(name + " case " + c.get("id") + ": produced " + produced);
            if (!r.open(c, "output_base64").equals(c.get("plaintext"))) throw new IllegalStateException(name + " case " + c.get("id") + ": decrypt mismatch");
        }
        List<Map<String, String>> negative = objects(Files.readString(vdir.resolve("negative.json")), new HashMap<>());
        for (var c : negative) {
            String opened;
            try { opened = r.open(c, "input_base64"); } catch (Exception e) { continue; }
            throw new IllegalStateException(name + " negative case " + c.get("id") + " (" + c.get("note") + ") returned plaintext: " + opened);
        }
        System.out.println("java: " + cases.size() + " cases and " + negative.size() + " negative cases OK for " + name);
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            for (var e : RECIPES.entrySet()) replay(e.getKey(), e.getValue());
            return;
        }
        String name = args[0];
        Recipe r = RECIPES.get(name);
        if (r == null) throw new IllegalArgumentException("unknown recipe " + name);
        if (args.length == 4 && args[1].equals("--emit")) {
            int n = Integer.parseInt(args[2]);
            StringBuilder b = new StringBuilder("{\"recipe\": \"" + name + "\", \"producer\": \"java\", \"items\": [\n");
            for (int i = 0; i < n; i++) {
                b.append(i > 0 ? ",\n{" : "{");
                boolean first = true;
                for (var f : r.emit(i).entrySet()) {
                    b.append(first ? "" : ", ").append('"').append(f.getKey()).append("\": \"").append(escape(f.getValue())).append('"');
                    first = false;
                }
                b.append("}");
            }
            Files.writeString(Path.of(args[3]), b.append("\n]}\n").toString());
            System.out.println("java: emitted " + n + " records to " + args[3] + " for " + name);
        } else if (args.length == 3 && args[1].equals("--consume")) {
            Map<String, String> top = new HashMap<>();
            List<Map<String, String>> items = objects(Files.readString(Path.of(args[2])), top);
            if (!name.equals(top.get("recipe"))) throw new IllegalStateException("recipe mismatch");
            for (var it : items)
                if (!r.consume(it).equals(it.get("plaintext"))) throw new IllegalStateException("java could not open a " + name + " record from " + top.get("producer"));
            System.out.println("java: opened " + items.size() + " " + name + " records from " + top.get("producer"));
        } else {
            throw new IllegalArgumentException("usage: Harness [<recipe> --emit N FILE | <recipe> --consume FILE]");
        }
    }
}
