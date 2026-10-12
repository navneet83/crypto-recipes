// Recipe aead-record-v1: encrypt a short record with a 32-byte key you already have.
// System.Security.Cryptography only, .NET 6+. Cipher is XAES-256-GCM (https://c2sp.org/XAES-256-GCM): a 24-byte
// random nonce, from which a per-message AES-256-GCM key is derived with one block of AES-CMAC, so random nonces
// are safe for any number of messages under one key.
//
// Key:    32 bytes, from a KMS, a key store or a KDF; never a password (see pbe-record-v1).
// Cipher: XAES-256-GCM, random 24-byte nonce, 16-byte tag, optional additional data (not stored).
// Output: Base64 of  version (1 byte, 0x01) || nonce (24) || ciphertext || tag (16).

using System.Security.Cryptography;
using System.Text;

namespace CryptoRecipes;

public static class AeadRecordV1
{
    public const string Recipe = "aead-record-v1";
    private const byte Version = 0x01;
    private const int KeyBytes = 32;
    private const int NonceBytes = 24;
    private const int TagBytes = 16;

    /// <summary>Steps 1-5 of the XAES-256-GCM key derivation: the per-message AES-256-GCM key. The GCM nonce is nonce[12..24).</summary>
    private static byte[] XaesSubkey(byte[] key, ReadOnlySpan<byte> nonce)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        byte[] l = aes.EncryptEcb(new byte[16], PaddingMode.None);
        byte[] k1 = new byte[16];
        for (int i = 0; i < 16; i++) k1[i] = (byte)((l[i] << 1) | (i < 15 ? l[i + 1] >> 7 : 0));
        if ((l[0] & 0x80) != 0) k1[15] ^= 0x87;
        byte[] kx = new byte[32];
        for (byte counter = 1; counter <= 2; counter++)
        {
            byte[] m = new byte[16];
            m[1] = counter; m[2] = 0x58;
            nonce[..12].CopyTo(m.AsSpan(4));
            for (int i = 0; i < 16; i++) m[i] ^= k1[i];
            aes.EncryptEcb(m, PaddingMode.None).CopyTo(kx, 16 * (counter - 1));
        }
        return kx;
    }

    /// <summary>nonce is null in normal use and generated here; the harness passes a fixed value to reproduce the vectors.</summary>
    public static string Encrypt(byte[] key, string plaintext, string aad = "", byte[]? nonce = null)
    {
        if (key.Length != KeyBytes) throw new ArgumentException("key must be 32 bytes");
        nonce ??= RandomNumberGenerator.GetBytes(NonceBytes);
        if (nonce.Length != NonceBytes) throw new ArgumentException("bad nonce length");
        byte[] pt = Encoding.UTF8.GetBytes(plaintext);
        byte[] output = new byte[1 + NonceBytes + pt.Length + TagBytes];
        output[0] = Version;
        nonce.CopyTo(output, 1);
        using var gcm = new AesGcm(XaesSubkey(key, nonce), TagBytes);
        gcm.Encrypt(nonce.AsSpan(12), pt, output.AsSpan(1 + NonceBytes, pt.Length), output.AsSpan(1 + NonceBytes + pt.Length, TagBytes), Encoding.UTF8.GetBytes(aad));
        return Convert.ToBase64String(output);
    }

    /// <summary>A wrong key, wrong additional data or any modification throws; there is never partial output.</summary>
    public static string Decrypt(byte[] key, string text, string aad = "")
    {
        if (key.Length != KeyBytes) throw new ArgumentException("key must be 32 bytes");
        byte[] data = Convert.FromBase64String(text);
        if (data.Length < 1 + NonceBytes + TagBytes || data[0] != Version) throw new CryptographicException("not an aead-record-v1 record");
        var nonce = data.AsSpan(1, NonceBytes);
        var ciphertext = data.AsSpan(1 + NonceBytes, data.Length - 1 - NonceBytes - TagBytes);
        var tag = data.AsSpan(data.Length - TagBytes, TagBytes);
        byte[] opened = new byte[ciphertext.Length];
        using var gcm = new AesGcm(XaesSubkey(key, nonce), TagBytes);
        gcm.Decrypt(nonce[12..], ciphertext, tag, opened, Encoding.UTF8.GetBytes(aad));
        return new UTF8Encoding(false, throwOnInvalidBytes: true).GetString(opened);
    }
}
