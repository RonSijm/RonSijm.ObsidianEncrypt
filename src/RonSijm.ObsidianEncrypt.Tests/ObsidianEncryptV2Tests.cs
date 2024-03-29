#pragma warning disable CS0618 // Type or member is obsolete

using FluentAssertions;

using RonSijm.ObsidianEncrypt.V2;

namespace RonSijm.ObsidianEncrypt.Tests;

public class ObsidianEncryptV2Tests
{
    [Theory]
    [InlineData("hello", "world")]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    [InlineData("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur.", "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur.")]
    public void CanEncryptAndDecryptV2Tests(string data, string password)
    {
        var obsidianEncryptV1 = new ObsidianEncryptV2(16, 16, 210000);
        var encrypted = obsidianEncryptV1.EncryptToBase64(data, password);
        encrypted.Should().NotBe(data);

        var decrypted = obsidianEncryptV1.DecryptFromBase64(encrypted, password);
        decrypted.Should().Be(data);
    }

    [Fact]
    public void CanDecryptV2Tests()
    {
        var obsidianEncryptV1 = new ObsidianEncryptV2(16, 16, 210000);

        // This is input encrypted inside Obsidian
        var input = "DCjjZmZk5rA8KhzdZPhM7RjXbDa7rfC11zfF65w2kgXtBYVXpzhRLyLWRu3MFidB7OrZ9DF7PLyaiylFkoJb8Siz";
        var password = "Obsidian Encrypted";

        var decrypted = obsidianEncryptV1.DecryptFromBase64(input, password);
        decrypted.Should().Be(password);
    }
}