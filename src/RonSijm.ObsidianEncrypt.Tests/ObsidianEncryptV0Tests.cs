using FluentAssertions;

using RonSijm.ObsidianEncrypt.V0;

namespace RonSijm.ObsidianEncrypt.Tests;

public class ObsidianEncryptV0Tests
{
    [Theory]
    [InlineData("hello", "world")]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    [InlineData("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur.", "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur.")]
    public void CanEncryptAndDecryptV0Tests(string data, string password)
    {
        var obsidianEncryptV0 = new ObsidianEncryptV0();
        var encrypted = obsidianEncryptV0.Encrypt(data, password);
        encrypted.Should().NotBe(data);

        var decrypted = obsidianEncryptV0.Decrypt(encrypted, password);
        decrypted.Should().Be(data);
    }
}