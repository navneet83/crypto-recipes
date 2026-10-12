// Recipe aead-record-v1: encrypt a short record with a 32-byte key you already have.
// JCA only (javax.crypto), Java 17+; works unchanged from Kotlin and on Android API 26+.
// Cipher is XAES-256-GCM (https://c2sp.org/XAES-256-GCM): a 24-byte random nonce, from which a per-message
// AES-256-GCM key is derived with one block of AES-CMAC, so random nonces are safe for any number of messages under one key.
//
// Key:    32 bytes, from a KMS, a key store or a KDF; never a password (see pbe-record-v1).
// Cipher: XAES-256-GCM, random 24-byte nonce, 16-byte tag, optional additional data (not stored).
// Output: Base64 of  version (1 byte, 0x01) || nonce (24) || ciphertext || tag (16).

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class AeadRecordV1 {
    public static final String RECIPE = "aead-record-v1";
    private static final byte VERSION = 0x01;
    private static final int KEY_BYTES = 32;
    private static final int NONCE_BYTES = 24;
    private static final int TAG_BITS = 128;
    private static final SecureRandom RANDOM = new SecureRandom();

    private static byte[] aesBlock(SecretKeySpec key, byte[] block) throws GeneralSecurityException {
        Cipher ecb = Cipher.getInstance("AES/ECB/NoPadding");
        ecb.init(Cipher.ENCRYPT_MODE, key);
        return ecb.doFinal(block);
    }

    /** Steps 1-5 of the XAES-256-GCM key derivation: the per-message AES-256-GCM key. The GCM nonce is nonce[12..24). */
    private static SecretKeySpec xaesSubkey(byte[] key, byte[] nonce) throws GeneralSecurityException {
        SecretKeySpec k = new SecretKeySpec(key, "AES");
        byte[] l = aesBlock(k, new byte[16]);
        byte[] k1 = new byte[16];
        for (int i = 0; i < 16; i++) k1[i] = (byte) ((l[i] << 1) | (i < 15 ? (l[i + 1] & 0xff) >>> 7 : 0));
        if ((l[0] & 0x80) != 0) k1[15] ^= (byte) 0x87;
        byte[] kx = new byte[32];
        for (int counter = 1; counter <= 2; counter++) {
            byte[] m = new byte[16];
            m[1] = (byte) counter; m[2] = 0x58;
            System.arraycopy(nonce, 0, m, 4, 12);
            for (int i = 0; i < 16; i++) m[i] ^= k1[i];
            System.arraycopy(aesBlock(k, m), 0, kx, 16 * (counter - 1), 16);
        }
        return new SecretKeySpec(kx, "AES");
    }

    private static Cipher gcm(int mode, byte[] key, byte[] nonce, byte[] aad) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(mode, xaesSubkey(key, nonce), new GCMParameterSpec(TAG_BITS, nonce, 12, 12));
        cipher.updateAAD(aad);
        return cipher;
    }

    /** nonce is null in normal use and generated here; the harness passes a fixed value to reproduce the vectors. */
    public static String encrypt(byte[] key, String plaintext, String aad, byte[] nonce) throws GeneralSecurityException {
        if (key.length != KEY_BYTES) throw new IllegalArgumentException("key must be 32 bytes");
        if (nonce == null) { nonce = new byte[NONCE_BYTES]; RANDOM.nextBytes(nonce); }
        if (nonce.length != NONCE_BYTES) throw new IllegalArgumentException("bad nonce length");
        byte[] sealed = gcm(Cipher.ENCRYPT_MODE, key, nonce, aad.getBytes(StandardCharsets.UTF_8)).doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        byte[] out = new byte[1 + NONCE_BYTES + sealed.length];
        out[0] = VERSION;
        System.arraycopy(nonce, 0, out, 1, NONCE_BYTES);
        System.arraycopy(sealed, 0, out, 1 + NONCE_BYTES, sealed.length);
        return Base64.getEncoder().encodeToString(out);
    }

    /** A wrong key, wrong additional data or any modification throws; there is never partial output. */
    public static String decrypt(byte[] key, String text, String aad) throws GeneralSecurityException {
        if (key.length != KEY_BYTES) throw new IllegalArgumentException("key must be 32 bytes");
        byte[] data = Base64.getDecoder().decode(text);
        if (data.length < 1 + NONCE_BYTES + TAG_BITS / 8 || data[0] != VERSION) throw new GeneralSecurityException("not an aead-record-v1 record");
        byte[] nonce = Arrays.copyOfRange(data, 1, 1 + NONCE_BYTES);
        byte[] opened = gcm(Cipher.DECRYPT_MODE, key, nonce, aad.getBytes(StandardCharsets.UTF_8)).doFinal(data, 1 + NONCE_BYTES, data.length - 1 - NONCE_BYTES);
        return new String(opened, StandardCharsets.UTF_8);
    }
}
