// Recipe sign-detached-pq-v1: sign a message and verify the signature, post-quantum.
// System.Security.Cryptography only, .NET 10+. MLDsa.IsSupported is true on Linux with OpenSSL 3.5+ and on Windows
// with the matching CNG update, and false on macOS as of .NET 10; check it before use.
//
// Keys:      ML-DSA-65 (FIPS 204). Private key is the 32-byte seed; public key is the 1952-byte encoding. Both Base64
//            when transported.
// Input:     "crypto-recipes/sign-detached-pq-v1" || 0x00 || message, with an empty FIPS 204 context string.
// Signature: the 3309 raw ML-DSA-65 bytes, Base64. Signing is randomized: two signatures of one message differ.

using System.Security.Cryptography;
using System.Text;

namespace CryptoRecipes;

public static class SignDetachedPqV1
{
    public const string Recipe = "sign-detached-pq-v1";
    public static bool Available => MLDsa.IsSupported;
    private static readonly byte[] Domain = Encoding.UTF8.GetBytes("crypto-recipes/sign-detached-pq-v1\0");
    private const int SeedBytes = 32, PublicBytes = 1952, SignatureBytes = 3309;

    private static byte[] Input(string message) => [.. Domain, .. Encoding.UTF8.GetBytes(message)];

    private static MLDsa PrivateKey(byte[] seed)
    {
        if (seed.Length != SeedBytes) throw new ArgumentException("seed must be 32 bytes");
        return MLDsa.ImportMLDsaPrivateSeed(MLDsaAlgorithm.MLDsa65, seed);
    }

    public static byte[] PublicKey(byte[] seed)
    {
        using var key = PrivateKey(seed);
        return key.ExportMLDsaPublicKey();
    }

    public static string Sign(byte[] seed, string message)
    {
        using var key = PrivateKey(seed);
        return Convert.ToBase64String(key.SignData(Input(message)));
    }

    /// <summary>Returns normally for a valid signature and throws for anything else; callers never get a boolean to ignore.</summary>
    public static void Verify(byte[] pub, string message, string signature)
    {
        if (pub.Length != PublicBytes) throw new ArgumentException("public key must be 1952 bytes");
        byte[] sig = Convert.FromBase64String(signature);
        if (sig.Length != SignatureBytes) throw new CryptographicException("signature must be 3309 bytes");
        using var key = MLDsa.ImportMLDsaPublicKey(MLDsaAlgorithm.MLDsa65, pub);
        if (!key.VerifyData(Input(message), sig)) throw new CryptographicException("invalid signature");
    }
}
