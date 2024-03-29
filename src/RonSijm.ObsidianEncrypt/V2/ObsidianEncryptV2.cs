using System.Text;

using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace RonSijm.ObsidianEncrypt.V2;

[Obsolete("This does not work yet!")]
public class ObsidianEncryptV2(int vectorSize, int saltSize, int iterations)
{
    private byte[] DeriveKey(string password, byte[] salt)
    {
        var generator = new Org.BouncyCastle.Crypto.Generators.Pkcs5S2ParametersGenerator();
        generator.Init(Encoding.UTF8.GetBytes(password), salt, iterations);
        return ((KeyParameter)generator.GenerateDerivedParameters("AES", 256)).GetKey();
    }

    private byte[] EncryptToBytes(string text, string password, byte[] salt, byte[] iv)
    {
        var cipher = new GcmBlockCipher(new AesEngine());
        var parameters = new AeadParameters(new KeyParameter(DeriveKey(password, salt)), 128, iv, null);
        cipher.Init(true, parameters);

        var textBytesToEncrypt = Encoding.UTF8.GetBytes(text);
        var output = new byte[cipher.GetOutputSize(textBytesToEncrypt.Length)];
        var len = cipher.ProcessBytes(textBytesToEncrypt, 0, textBytesToEncrypt.Length, output, 0);
        cipher.DoFinal(output, len);
        return output;
    }

    private string ConvertToString(byte[] bytes)
    {
        return Convert.ToBase64String(bytes);
    }

    public string EncryptToBase64(string text, string password)
    {
        var salt = new byte[saltSize];
        var iv = new byte[vectorSize];
        SecureRandom.GetInstance("SHA1PRNG").NextBytes(salt);
        SecureRandom.GetInstance("SHA1PRNG").NextBytes(iv);

        var finalBytes = EncryptToBytes(text, password, salt, iv);

        var result = new byte[iv.Length + salt.Length + finalBytes.Length];
        Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
        Buffer.BlockCopy(salt, 0, result, iv.Length, salt.Length);
        Buffer.BlockCopy(finalBytes, 0, result, iv.Length + salt.Length, finalBytes.Length);

        return ConvertToString(result);
    }

    private byte[] DecryptFromBytes(byte[] encryptedBytes, string password, byte[] salt, byte[] iv)
    {
        var cipher = new GcmBlockCipher(new AesEngine());
        var parameters = new AeadParameters(new KeyParameter(DeriveKey(password, salt)), 128, iv, null);
        cipher.Init(false, parameters);

        var output = new byte[cipher.GetOutputSize(encryptedBytes.Length)];
        var len = cipher.ProcessBytes(encryptedBytes, 0, encryptedBytes.Length, output, 0);
        cipher.DoFinal(output, len);
        return output;
    }

    public string DecryptFromBase64(string base64Encoded, string password)
    {
        var bytesToDecode = Convert.FromBase64String(base64Encoded);
        var iv = new byte[vectorSize];
        var salt = new byte[saltSize];
        var encryptedTextBytes = new byte[bytesToDecode.Length - iv.Length - salt.Length];
        Buffer.BlockCopy(bytesToDecode, 0, iv, 0, iv.Length);
        Buffer.BlockCopy(bytesToDecode, iv.Length, salt, 0, salt.Length);
        Buffer.BlockCopy(bytesToDecode, iv.Length + salt.Length, encryptedTextBytes, 0, encryptedTextBytes.Length);

        var decryptedBytes = DecryptFromBytes(encryptedTextBytes, password, salt, iv);
        return Encoding.UTF8.GetString(decryptedBytes);
    }
}