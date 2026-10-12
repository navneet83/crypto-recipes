// Recipe pbe-record-pbkdf2-gcm-v1: encrypt a short record with a password.
// JCA only (javax.crypto), Java 17+. Works unchanged from Kotlin and on Android API 26+.
//
// Key:    PBKDF2-HMAC-SHA256, 600000 iterations, random 16-byte salt, over the UTF-8 bytes of the password.
// Cipher: AES-256-GCM, random 12-byte nonce, 16-byte tag, no additional data.
// Output: Base64 of  version (1 byte, 0x01) || salt (16) || nonce (12) || ciphertext || tag (16).
// This is the fallback profile of recipe R1; see RECIPES.md for the Argon2id and XAES-256-GCM profiles.
// Run the harness as a single-file program: java PbeRecordPbkdf2GcmV1.java [--emit N FILE | --consume FILE]

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public final class PbeRecordPbkdf2GcmV1 {
    public static final String RECIPE = "pbe-record-pbkdf2-gcm-v1";
    private static final byte VERSION = 0x01;
    private static final int ITERATIONS = 600_000;
    private static final int SALT_BYTES = 16;
    private static final int NONCE_BYTES = 12;
    private static final int TAG_BITS = 128;
    private static final SecureRandom RANDOM = new SecureRandom();

    private static SecretKeySpec deriveKey(String password, byte[] salt) throws GeneralSecurityException {
        // PBEKeySpec takes chars; the JCA PBKDF2 implementation encodes them as UTF-8, matching the other languages.
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, 256);
        try {
            byte[] key = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
            return new SecretKeySpec(key, "AES");
        } finally {
            spec.clearPassword();
        }
    }

    private static byte[] random(int n) {
        byte[] b = new byte[n];
        RANDOM.nextBytes(b);
        return b;
    }

    /** salt and nonce are null in normal use and generated here; the harness passes fixed values to reproduce the vectors. */
    public static String encrypt(String password, String plaintext, byte[] salt, byte[] nonce) throws GeneralSecurityException {
        if (salt == null) salt = random(SALT_BYTES);
        if (nonce == null) nonce = random(NONCE_BYTES);
        if (salt.length != SALT_BYTES || nonce.length != NONCE_BYTES) throw new IllegalArgumentException("bad salt or nonce length");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, deriveKey(password, salt), new GCMParameterSpec(TAG_BITS, nonce));
        byte[] sealed = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        byte[] out = new byte[1 + SALT_BYTES + NONCE_BYTES + sealed.length];
        out[0] = VERSION;
        System.arraycopy(salt, 0, out, 1, SALT_BYTES);
        System.arraycopy(nonce, 0, out, 1 + SALT_BYTES, NONCE_BYTES);
        System.arraycopy(sealed, 0, out, 1 + SALT_BYTES + NONCE_BYTES, sealed.length);
        return Base64.getEncoder().encodeToString(out);
    }

    /** A wrong password or any modification throws; there is never partial output. */
    public static String decrypt(String password, String text) throws GeneralSecurityException {
        byte[] data = Base64.getDecoder().decode(text);
        if (data.length < 1 + SALT_BYTES + NONCE_BYTES + TAG_BITS / 8 || data[0] != VERSION)
            throw new GeneralSecurityException("not a pbe-record-pbkdf2-gcm-v1 record");
        byte[] salt = Arrays.copyOfRange(data, 1, 1 + SALT_BYTES);
        byte[] nonce = Arrays.copyOfRange(data, 1 + SALT_BYTES, 1 + SALT_BYTES + NONCE_BYTES);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, deriveKey(password, salt), new GCMParameterSpec(TAG_BITS, nonce));
        int start = 1 + SALT_BYTES + NONCE_BYTES;
        byte[] opened = cipher.doFinal(data, start, data.length - start);
        return new String(opened, StandardCharsets.UTF_8);
    }

    // Harness. A tiny JSON reader keeps this a single file with no dependencies; it handles the vector files only.
    /** Reads the JSON string literal that starts at json[i] == '"'; returns the decoded value and the index after the closing quote. */
    private static java.util.Map.Entry<String, Integer> readString(String json, int i) {
        StringBuilder b = new StringBuilder();
        for (i++; ; i++) {
            char c = json.charAt(i);
            if (c == '"') return java.util.Map.entry(b.toString(), i + 1);
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

    private static String escape(String s) {
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
    private static List<java.util.Map<String, String>> objects(String json, java.util.Map<String, String> top) {
        List<java.util.Map<String, String>> out = new ArrayList<>();
        java.util.Map<String, String> current = null;
        int depth = 0;
        String pendingKey = null;
        for (int i = 0; i < json.length(); ) {
            char c = json.charAt(i);
            if (c == '"') {
                var e = readString(json, i);
                i = e.getValue();
                java.util.Map<String, String> target = depth == 1 ? top : depth == 2 ? current : null;
                if (pendingKey == null) pendingKey = e.getKey();
                else { if (target != null) target.put(pendingKey, e.getKey()); pendingKey = null; }
                continue;
            }
            if (c == '{') { if (++depth == 2) current = new java.util.HashMap<>(); }
            else if (c == '}') { if (depth-- == 2) out.add(current); }
            else if (c == '[' || c == ']' || c == ',') pendingKey = null;
            i++;
        }
        return out;
    }

    private static byte[] hex(String s) {
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) b[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        return b;
    }

    public static void main(String[] args) throws Exception {
        Path vdir = Path.of(System.getProperty("recipes.root", ".")).resolve("vectors").resolve(RECIPE);
        if (args.length == 3 && args[0].equals("--emit")) {
            int n = Integer.parseInt(args[1]);
            StringBuilder b = new StringBuilder("{\"recipe\": \"" + RECIPE + "\", \"producer\": \"java\", \"items\": [\n");
            for (int i = 0; i < n; i++) {
                String password = "pw-" + i + "-" + UUID.randomUUID();
                String plaintext = i % 3 == 0 ? "" : "record " + i + " " + "x".repeat(i * 7) + " ünïcödé ✓";
                b.append(i > 0 ? ",\n" : "").append("{\"password\": \"").append(escape(password)).append("\", \"plaintext\": \"")
                 .append(escape(plaintext)).append("\", \"record\": \"").append(encrypt(password, plaintext, null, null)).append("\"}");
            }
            Files.writeString(Path.of(args[2]), b.append("\n]}\n").toString());
            System.out.println("java: emitted " + n + " records to " + args[2]);
        } else if (args.length == 2 && args[0].equals("--consume")) {
            java.util.Map<String, String> top = new java.util.HashMap<>();
            List<java.util.Map<String, String>> items = objects(Files.readString(Path.of(args[1])), top);
            if (!RECIPE.equals(top.get("recipe"))) throw new IllegalStateException("recipe mismatch");
            String producer = top.get("producer");
            for (var it : items)
                if (!decrypt(it.get("password"), it.get("record")).equals(it.get("plaintext")))
                    throw new IllegalStateException("java could not open a record from " + producer);
            System.out.println("java: opened " + items.size() + " records from " + producer);
        } else {
            List<java.util.Map<String, String>> cases = objects(Files.readString(vdir.resolve("cases.json")), new java.util.HashMap<>());
            for (var c : cases) {
                String produced = encrypt(c.get("password"), c.get("plaintext"), hex(c.get("salt_hex")), hex(c.get("nonce_hex")));
                if (!produced.equals(c.get("output_base64"))) throw new IllegalStateException("case " + c.get("id") + ": produced " + produced);
                if (!decrypt(c.get("password"), c.get("output_base64")).equals(c.get("plaintext"))) throw new IllegalStateException("case " + c.get("id") + ": decrypt mismatch");
            }
            List<java.util.Map<String, String>> negative = objects(Files.readString(vdir.resolve("negative.json")), new java.util.HashMap<>());
            for (var c : negative) {
                String opened;
                try { opened = decrypt(c.get("password"), c.get("input_base64")); } catch (Exception e) { continue; }
                throw new IllegalStateException("negative case " + c.get("id") + " (" + c.get("note") + ") returned plaintext: " + opened);
            }
            System.out.println("java: " + cases.size() + " cases and " + negative.size() + " negative cases OK for " + RECIPE);
        }
    }
}
