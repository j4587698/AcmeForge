using System.Buffers.Text;

namespace AcmeForge;

/// <summary>RFC 4648 base64url 辅助（无填充）。</summary>
internal static class Base64UrlText
{
    public static string Encode(ReadOnlySpan<byte> data) => Base64Url.EncodeToString(data);

    public static string Encode(byte[] data) => Base64Url.EncodeToString(data);

    public static byte[] Decode(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return Array.Empty<byte>();
        }

        return Base64Url.DecodeFromChars(value.AsSpan());
    }
}
