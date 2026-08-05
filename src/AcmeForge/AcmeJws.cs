using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace AcmeForge;

/// <summary>
/// ACME JWS (RFC 7515) 签名辅助：构造 protected header、签名、生成请求体。
/// </summary>
internal static class AcmeJws
{
    public static string Sign(AcmeKey key, string url, string nonce, bool includeJwk, string? kid, string payloadBase64Url)
    {
        var headerJson = BuildProtectedHeader(key, url, nonce, includeJwk, kid);
        return BuildJwsObject(headerJson, payloadBase64Url, key.Sign(SigningInput(headerJson, payloadBase64Url)));
    }

    /// <summary>构造 protected header JSON。</summary>
    public static string BuildProtectedHeader(AcmeKey key, string url, string nonce, bool includeJwk, string? kid)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteString("alg", key.JwsAlgorithm);
            if (includeJwk)
            {
                writer.WritePropertyName("jwk");
                writer.WriteRawValue(key.GetJwkCanonicalJson(), skipInputValidation: true);
            }
            else
            {
                writer.WriteString("kid", kid);
            }

            writer.WriteString("nonce", nonce);
            writer.WriteString("url", url);
            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(buffer.ToArray());
    }

    /// <summary>RFC 8555 §7.3.4 External Account Binding：HS256，payload 为账户密钥 JWK 指纹。</summary>
    public static string BuildExternalAccountBinding(AcmeKey accountKey, string eabKid, string eabHmacKey, string newAccountUrl)
    {
        string headerJson;
        using (var buffer = new MemoryStream())
        {
            using (var writer = new Utf8JsonWriter(buffer))
            {
                writer.WriteStartObject();
                writer.WriteString("alg", "HS256");
                writer.WriteString("kid", eabKid);
                writer.WriteString("url", newAccountUrl);
                writer.WritePropertyName("jwk");
                writer.WriteRawValue(accountKey.GetJwkCanonicalJson(), skipInputValidation: true);
                writer.WriteEndObject();
            }

            headerJson = Encoding.UTF8.GetString(buffer.ToArray());
        }

        var payload = Base64UrlText.Encode(Encoding.UTF8.GetBytes(accountKey.GetJwkThumbprint()));
        var signingInput = SigningInput(headerJson, payload);
        using var hmac = new HMACSHA256(DecodeEabHmacKey(eabHmacKey));
        var signature = hmac.ComputeHash(signingInput);
        return BuildJwsObject(headerJson, payload, signature);
    }

    private static byte[] SigningInput(string headerJson, string payloadBase64Url)
    {
        var headerBase64 = Base64UrlText.Encode(Encoding.UTF8.GetBytes(headerJson));
        return Encoding.ASCII.GetBytes(headerBase64 + "." + payloadBase64Url);
    }

    private static string BuildJwsObject(string headerJson, string payloadBase64Url, byte[] signature)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteString("protected", Base64UrlText.Encode(Encoding.UTF8.GetBytes(headerJson)));
            writer.WriteString("payload", payloadBase64Url);
            writer.WriteString("signature", Base64UrlText.Encode(signature));
            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(buffer.ToArray());
    }

    private static byte[] DecodeEabHmacKey(string hmacKey)
    {
        if (string.IsNullOrWhiteSpace(hmacKey))
        {
            throw new ArgumentException("EAB HMAC 密钥为空", nameof(hmacKey));
        }

        try
        {
            return Base64UrlText.Decode(hmacKey);
        }
        catch (FormatException)
        {
            // 允许标准 base64 或原始字节
        }

        try
        {
            return Convert.FromBase64String(hmacKey);
        }
        catch (FormatException)
        {
            return Encoding.UTF8.GetBytes(hmacKey);
        }
    }
}
