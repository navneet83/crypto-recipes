// Recipe hpke-envelope-v1: encrypt a short record to a recipient's public key.
// JCA only, Java 26+ (the "HPKE" Cipher); works unchanged from Kotlin.
//
// Suite:  HPKE (RFC 9180) base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM, single-shot, no additional data.
// Info:   "crypto-recipes/hpke-envelope-v1", which binds every record to this recipe.
// Keys:   recipient private key is the 32-byte X25519 scalar, public key the 32-byte point. The JDK takes the scalar as
//         XECPrivateKeySpec and the point in its X.509 form, the fixed 12-byte prefix below followed by the 32 bytes.
// Output: Base64 of  version (1 byte, 0x01) || enc (32) || ciphertext || tag (16).

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.NamedParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.XECPrivateKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import javax.crypto.Cipher;
import javax.crypto.spec.HPKEParameterSpec;

public final class HpkeEnvelopeV1 {
    public static final String RECIPE = "hpke-envelope-v1";
    private static final byte VERSION = 0x01;
    private static final byte[] INFO = "crypto-recipes/hpke-envelope-v1".getBytes(StandardCharsets.UTF_8);
    private static final int KEY_BYTES = 32, ENC_BYTES = 32, TAG_BYTES = 16;
    private static final byte[] X509_PREFIX = HexFormat.of().parseHex("302a300506032b656e032100");
    private static final HPKEParameterSpec SUITE = HPKEParameterSpec.of(
        HPKEParameterSpec.KEM_DHKEM_X25519_HKDF_SHA256, HPKEParameterSpec.KDF_HKDF_SHA256, HPKEParameterSpec.AEAD_AES_256_GCM).withInfo(INFO);

    private static PrivateKey privateKey(byte[] scalar) throws GeneralSecurityException {
        if (scalar.length != KEY_BYTES) throw new IllegalArgumentException("private key must be 32 bytes");
        return KeyFactory.getInstance("X25519").generatePrivate(new XECPrivateKeySpec(NamedParameterSpec.X25519, scalar));
    }

    private static PublicKey publicKeyOf(byte[] point) throws GeneralSecurityException {
        if (point.length != KEY_BYTES) throw new IllegalArgumentException("public key must be 32 bytes");
        byte[] encoded = Arrays.copyOf(X509_PREFIX, X509_PREFIX.length + KEY_BYTES);
        System.arraycopy(point, 0, encoded, X509_PREFIX.length, KEY_BYTES);
        return KeyFactory.getInstance("X25519").generatePublic(new X509EncodedKeySpec(encoded));
    }

    /** The JDK does not expose the public half of a private key, so the pair is regenerated from the scalar. */
    public static byte[] publicKey(byte[] scalar) throws GeneralSecurityException {
        if (scalar.length != KEY_BYTES) throw new IllegalArgumentException("private key must be 32 bytes");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519");
        kpg.initialize(NamedParameterSpec.X25519, new SecureRandom() {
            @Override public void nextBytes(byte[] out) {
                if (out.length != KEY_BYTES) throw new IllegalStateException("provider asked for " + out.length + " random bytes");
                System.arraycopy(scalar, 0, out, 0, KEY_BYTES);
            }
        });
        byte[] encoded = kpg.generateKeyPair().getPublic().getEncoded();
        return Arrays.copyOfRange(encoded, encoded.length - KEY_BYTES, encoded.length);
    }

    public static String encrypt(byte[] publicKey, String plaintext) throws GeneralSecurityException {
        Cipher c = Cipher.getInstance("HPKE");
        c.init(Cipher.ENCRYPT_MODE, publicKeyOf(publicKey), SUITE);
        byte[] enc = c.getIV();
        byte[] sealed = c.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        byte[] out = new byte[1 + enc.length + sealed.length];
        out[0] = VERSION;
        System.arraycopy(enc, 0, out, 1, enc.length);
        System.arraycopy(sealed, 0, out, 1 + enc.length, sealed.length);
        return Base64.getEncoder().encodeToString(out);
    }

    /** A wrong key or any modification throws; there is never partial output. */
    public static String decrypt(byte[] privateKey, String text) throws GeneralSecurityException {
        byte[] data = Base64.getDecoder().decode(text);
        if (data.length < 1 + ENC_BYTES + TAG_BYTES || data[0] != VERSION) throw new GeneralSecurityException("not an hpke-envelope-v1 record");
        Cipher c = Cipher.getInstance("HPKE");
        c.init(Cipher.DECRYPT_MODE, privateKey(privateKey), SUITE.withEncapsulation(Arrays.copyOfRange(data, 1, 1 + ENC_BYTES)));
        return new String(c.doFinal(data, 1 + ENC_BYTES, data.length - 1 - ENC_BYTES), StandardCharsets.UTF_8);
    }
}
