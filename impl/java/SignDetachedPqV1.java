// Recipe sign-detached-pq-v1: sign a message and verify the signature, post-quantum.
// JCA only, Java 24+; works unchanged from Kotlin.
//
// Keys:      ML-DSA-65 (FIPS 204). Private key is the 32-byte seed; public key is the 1952-byte encoding. Both Base64
//            when transported. The JDK imports the seed through its PKCS#8 form (fixed 22-byte prefix + seed) and the
//            public key through its X.509 form (fixed 22-byte prefix + 1952 bytes); the prefixes are below.
// Input:     "crypto-recipes/sign-detached-pq-v1" || 0x00 || message, with an empty FIPS 204 context string. The JDK
//            (as of Java 27) does not expose the context parameter, which is one reason the recipe uses a prefix.
// Signature: the 3309 raw ML-DSA-65 bytes, Base64. Signing is randomized: two signatures of one message differ.

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;

public final class SignDetachedPqV1 {
    public static final String RECIPE = "sign-detached-pq-v1";
    private static final byte[] DOMAIN = "crypto-recipes/sign-detached-pq-v1\0".getBytes(StandardCharsets.UTF_8);
    private static final int SEED_BYTES = 32, PUBLIC_BYTES = 1952, SIGNATURE_BYTES = 3309;
    private static final byte[] PKCS8_PREFIX = HexFormat.of().parseHex("3034020100300b060960864801650304031204228020");
    private static final byte[] X509_PREFIX = HexFormat.of().parseHex("308207b2300b0609608648016503040312038207a100");

    public static boolean available() {
        try { KeyFactory.getInstance("ML-DSA-65"); return true; } catch (GeneralSecurityException e) { return false; }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static PrivateKey privateKey(byte[] seed) throws GeneralSecurityException {
        if (seed.length != SEED_BYTES) throw new IllegalArgumentException("seed must be 32 bytes");
        return KeyFactory.getInstance("ML-DSA-65").generatePrivate(new PKCS8EncodedKeySpec(concat(PKCS8_PREFIX, seed)));
    }

    /** As with Ed25519, the JDK does not expose the public half of a private key, so the pair is regenerated from the seed. */
    public static byte[] publicKey(byte[] seed) throws GeneralSecurityException {
        if (seed.length != SEED_BYTES) throw new IllegalArgumentException("seed must be 32 bytes");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-65");
        kpg.initialize(NamedParameterSpec.ML_DSA_65, new SeedRandom(seed));
        byte[] encoded = kpg.generateKeyPair().getPublic().getEncoded();
        return Arrays.copyOfRange(encoded, encoded.length - PUBLIC_BYTES, encoded.length);
    }

    private static final class SeedRandom extends SecureRandom {
        private final byte[] seed;
        SeedRandom(byte[] seed) { this.seed = seed.clone(); }
        @Override public void nextBytes(byte[] out) {
            if (out.length != seed.length) throw new IllegalStateException("provider asked for " + out.length + " random bytes, not a 32-byte seed");
            System.arraycopy(seed, 0, out, 0, out.length);
        }
    }

    public static String sign(byte[] seed, String message) throws GeneralSecurityException {
        Signature s = Signature.getInstance("ML-DSA");
        s.initSign(privateKey(seed));
        s.update(concat(DOMAIN, message.getBytes(StandardCharsets.UTF_8)));
        return Base64.getEncoder().encodeToString(s.sign());
    }

    /** Returns normally for a valid signature and throws for anything else; callers never get a boolean to ignore. */
    public static void verify(byte[] pub, String message, String signature) throws GeneralSecurityException {
        if (pub.length != PUBLIC_BYTES) throw new IllegalArgumentException("public key must be 1952 bytes");
        byte[] sig = Base64.getDecoder().decode(signature);
        if (sig.length != SIGNATURE_BYTES) throw new SignatureException("signature must be 3309 bytes");
        PublicKey key = KeyFactory.getInstance("ML-DSA-65").generatePublic(new X509EncodedKeySpec(concat(X509_PREFIX, pub)));
        Signature s = Signature.getInstance("ML-DSA");
        s.initVerify(key);
        s.update(concat(DOMAIN, message.getBytes(StandardCharsets.UTF_8)));
        if (!s.verify(sig)) throw new SignatureException("invalid signature");
    }
}
