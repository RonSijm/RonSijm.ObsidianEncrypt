using System.Security.Cryptography;
using System.Text;

namespace RonSijm.ObsidianEncrypt.V0;

public class ObsidianEncryptV0
{
    public ObsidianEncryptV0Result Encrypt(string text, string password)
    {
        var key = DeriveKey(password);
        var plaintextBytes = Encoding.UTF8.GetBytes(text);

        using var aesGcm = new AesGcm(key, ObsidianEncryptV0Config.TagLength);

        var cipherText = new byte[plaintextBytes.Length];
        var tag = new byte[ObsidianEncryptV0Config.TagLength];
        aesGcm.Encrypt(ObsidianEncryptV0Config.IV, plaintextBytes, cipherText, tag);

        var result = new byte[cipherText.Length + tag.Length];
        Buffer.BlockCopy(cipherText, 0, result, 0, cipherText.Length);
        Buffer.BlockCopy(tag, 0, result, cipherText.Length, tag.Length);

        var resultEncoded = Convert.ToBase64String(result);

        return new ObsidianEncryptV0Result { Value = resultEncoded };
    }

    public string Decrypt(ObsidianEncryptV0Result result, string password)
    {
        return Decrypt(result.Value, password);
    }

    public string Decrypt(string base64Encoded, string password)
    {
        try
        {
            var key = DeriveKey(password);
            var cipherWithTag = Convert.FromBase64String(base64Encoded);
            var cipherText = new byte[cipherWithTag.Length - ObsidianEncryptV0Config.TagLength];
            var tag = new byte[ObsidianEncryptV0Config.TagLength];
            Buffer.BlockCopy(cipherWithTag, 0, cipherText, 0, cipherText.Length);
            Buffer.BlockCopy(cipherWithTag, cipherText.Length, tag, 0, tag.Length);

            using var aesGcm = new AesGcm(key, ObsidianEncryptV0Config.TagLength);

            var decryptedBytes = new byte[cipherText.Length];
            aesGcm.Decrypt(ObsidianEncryptV0Config.IV, cipherText, tag, decryptedBytes);

            return Encoding.UTF8.GetString(decryptedBytes);
        }
        catch (Exception e)
        {
            Console.WriteLine(e.Message);
            return null;
        }
    }

    private byte[] DeriveKey(string password)
    {
        var passwordBytes = Encoding.UTF8.GetBytes(password);

        using var sha256 = SHA256.Create();

        return sha256.ComputeHash(passwordBytes);
    }
}