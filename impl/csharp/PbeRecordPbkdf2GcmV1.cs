// Recipe pbe-record-pbkdf2-gcm-v1: encrypt a short record with a password.
// System.Security.Cryptography only, .NET 6+ (AesGcm with a 16-byte tag, Rfc2898DeriveBytes.Pbkdf2).
//
// Key:    PBKDF2-HMAC-SHA256, 600000 iterations, random 16-byte salt, over the UTF-8 bytes of the password.
// Cipher: AES-256-GCM, random 12-byte nonce, 16-byte tag, no additional data.
// Output: Base64 of  version (1 byte, 0x01) || salt (16) || nonce (12) || ciphertext || tag (16).
// This is the fallback profile of recipe R1; see RECIPES.md for the Argon2id and XAES-256-GCM profiles.

using System.Security.Cryptography;
using System.Text;

namespace CryptoRecipes;

public static class PbeRecordPbkdf2GcmV1
{
    public const string Recipe = "pbe-record-pbkdf2-gcm-v1";
    private const byte Version = 0x01;
    private const int Iterations = 600_000;
    private const int SaltBytes = 16;
    private const int NonceBytes = 12;
    private const int TagBytes = 16;

    private static byte[] DeriveKey(string password, ReadOnlySpan<byte> salt) =>
        Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), salt, Iterations, HashAlgorithmName.SHA256, 32);

    /// <summary>salt and nonce are null in normal use and generated here; the harness passes fixed values to reproduce the vectors.</summary>
    public static string Encrypt(string password, string plaintext, byte[]? salt = null, byte[]? nonce = null)
    {
        salt ??= RandomNumberGenerator.GetBytes(SaltBytes);
        nonce ??= RandomNumberGenerator.GetBytes(NonceBytes);
        if (salt.Length != SaltBytes || nonce.Length != NonceBytes) throw new ArgumentException("bad salt or nonce length");
        byte[] pt = Encoding.UTF8.GetBytes(plaintext);
        byte[] output = new byte[1 + SaltBytes + NonceBytes + pt.Length + TagBytes];
        output[0] = Version;
        salt.CopyTo(output, 1);
        nonce.CopyTo(output, 1 + SaltBytes);
        var ciphertext = output.AsSpan(1 + SaltBytes + NonceBytes, pt.Length);
        var tag = output.AsSpan(1 + SaltBytes + NonceBytes + pt.Length, TagBytes);
        using var aes = new AesGcm(DeriveKey(password, salt), TagBytes);
        aes.Encrypt(nonce, pt, ciphertext, tag);
        return Convert.ToBase64String(output);
    }

    /// <summary>A wrong password or any modification throws; there is never partial output.</summary>
    public static string Decrypt(string password, string text)
    {
        byte[] data = Convert.FromBase64String(text);
        if (data.Length < 1 + SaltBytes + NonceBytes + TagBytes || data[0] != Version)
            throw new CryptographicException("not a pbe-record-pbkdf2-gcm-v1 record");
        var salt = data.AsSpan(1, SaltBytes);
        var nonce = data.AsSpan(1 + SaltBytes, NonceBytes);
        var ciphertext = data.AsSpan(1 + SaltBytes + NonceBytes, data.Length - 1 - SaltBytes - NonceBytes - TagBytes);
        var tag = data.AsSpan(data.Length - TagBytes, TagBytes);
        byte[] opened = new byte[ciphertext.Length];
        using var aes = new AesGcm(DeriveKey(password, salt), TagBytes);
        aes.Decrypt(nonce, ciphertext, tag, opened);
        return new UTF8Encoding(false, throwOnInvalidBytes: true).GetString(opened);
    }
}
