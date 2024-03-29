namespace RonSijm.ObsidianEncrypt.V0;

public class ObsidianEncryptV0Result
{
    public string Value { get; set; }

    public string ObsidianValue => $"%%🔐 {Value} 🔐";
}