namespace RonSijm.ObsidianEncrypt.V0;

public static class ObsidianEncryptV0Config
{
    public static byte[] IV { get; } = [196, 190, 240, 190, 188, 78, 41, 132, 15, 220, 84, 211];
    public static int TagLength => 16;
}