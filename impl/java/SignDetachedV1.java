// Recipe sign-detached-v1: sign a message and verify the signature.
// JCA only, Java 15+; works unchanged from Kotlin. (Android has Ed25519 in the platform provider from API 33;
// older Android needs Conscrypt or Bouncy Castle.)
//
// Keys:      Ed25519 (RFC 8032). Private key is the 32-byte seed, public key is the 32-byte point, both Base64 when
//            transported. JCA imports keys only in PKCS#8 / X.509 form, so the raw bytes are wrapped in the fixed
//            DER prefixes below; that is an encoding, not a different key.
// Input:     "crypto-recipes/sign-detached-v1" || 0x00 || message. The prefix stops a signature made for this recipe
//            from meaning anything in another protocol that signs raw bytes with the same key, and the other way round.
// Signature: the 64 raw Ed25519 bytes, Base64 (standard alphabet, with padding). The public key and the message
//            travel separately, which is what "detached" means.

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

public final class SignDetachedV1 {
    public static final String RECIPE = "sign-detached-v1";
    private static final byte[] DOMAIN = "crypto-recipes/sign-detached-v1\0".getBytes(StandardCharsets.UTF_8);
    private static final int SEED_BYTES = 32, PUBLIC_BYTES = 32, SIGNATURE_BYTES = 64;
    private static final byte[] PKCS8_PREFIX = {0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20};
    private static final byte[] X509_PREFIX = {0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00};

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static PrivateKey privateKey(byte[] seed) throws GeneralSecurityException {
        if (seed.length != SEED_BYTES) throw new IllegalArgumentException("seed must be 32 bytes");
        return KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(concat(PKCS8_PREFIX, seed)));
    }

    /**
     * The JDK does not expose the public half of an EdEC private key, so the pair is regenerated from the seed:
     * SunEC's Ed25519 generator draws exactly the 32-byte seed from its SecureRandom. The vectors catch a provider
     * that does otherwise. The public key is the last 32 bytes of the X.509 encoding.
     */
    public static byte[] publicKey(byte[] seed) throws GeneralSecurityException {
        if (seed.length != SEED_BYTES) throw new IllegalArgumentException("seed must be 32 bytes");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
        kpg.initialize(NamedParameterSpec.ED25519, new SeedRandom(seed));
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
        Signature s = Signature.getInstance("Ed25519");
        s.initSign(privateKey(seed));
        s.update(concat(DOMAIN, message.getBytes(StandardCharsets.UTF_8)));
        return Base64.getEncoder().encodeToString(s.sign());
    }

    /** Returns normally for a valid signature and throws for anything else; callers never get a boolean to ignore. */
    public static void verify(byte[] pub, String message, String signature) throws GeneralSecurityException {
        if (pub.length != PUBLIC_BYTES) throw new IllegalArgumentException("public key must be 32 bytes");
        byte[] sig = Base64.getDecoder().decode(signature);
        if (sig.length != SIGNATURE_BYTES) throw new SignatureException("signature must be 64 bytes");
        PublicKey key = KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(concat(X509_PREFIX, pub)));
        Signature s = Signature.getInstance("Ed25519");
        s.initVerify(key);
        s.update(concat(DOMAIN, message.getBytes(StandardCharsets.UTF_8)));
        if (!s.verify(sig)) throw new SignatureException("invalid signature");
    }
}
