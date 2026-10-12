// Recipe pbe-record-pbkdf2-gcm-v1: encrypt a short record with a password.
// JCA only (javax.crypto), Java 17+. Works unchanged from Kotlin and on Android API 26+.
//
// Key:    PBKDF2-HMAC-SHA256, 600000 iterations, random 16-byte salt, over the UTF-8 bytes of the password.
// Cipher: AES-256-GCM, random 12-byte nonce, 16-byte tag, no additional data.
// Output: Base64 of  version (1 byte, 0x01) || salt (16) || nonce (12) || ciphertext || tag (16).
// This is the fallback profile of recipe R1; see RECIPES.md for the Argon2id and XAES-256-GCM profiles.

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
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
}
