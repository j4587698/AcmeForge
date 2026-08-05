using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AcmeForge;

namespace AcmeForge.Tests;

public class AcmeJwsTests
{
    [Fact]
    public void Sign_WithJwk_ProducesValidJws()
    {
        using var key = AcmeKey.Generate(AcmeKeyAlgorithm.ES256);
        var jws = AcmeJws.Sign(key, "https://acme.test/new-account", "nonce-1", includeJwk: true, kid: null, "cGF5bG9hZA");

        using var doc = JsonDocument.Parse(jws);
        var root = doc.RootElement;

        Assert.True(root.TryGetProperty("protected", out var protectedEl));
        Assert.True(root.TryGetProperty("payload", out var payloadEl));
        Assert.True(root.TryGetProperty("signature", out var sigEl));
        Assert.Equal("cGF5bG9hZA", payloadEl.GetString());

        var protectedJson = Encoding.UTF8.GetString(Base64UrlDecode(protectedEl.GetString()!));
        using var headerDoc = JsonDocument.Parse(protectedJson);
        var header = headerDoc.RootElement;

        Assert.Equal("ES256", header.GetProperty("alg").GetString());
        Assert.Equal("nonce-1", header.GetProperty("nonce").GetString());
        Assert.Equal("https://acme.test/new-account", header.GetProperty("url").GetString());
        Assert.True(header.TryGetProperty("jwk", out var jwk));
        Assert.Equal(key.GetJwkCanonicalJson(), jwk.GetRawText());
        Assert.False(header.TryGetProperty("kid", out _));

        // 独立验证签名：signing input = ASCII(protected "." payload)
        var signingInput = Encoding.ASCII.GetBytes(protectedEl.GetString() + "." + payloadEl.GetString());
        Assert.True(key.Verify(signingInput, Base64UrlDecode(sigEl.GetString()!)));
    }

    [Fact]
    public void Sign_WithKid_OmitsJwk()
    {
        using var key = AcmeKey.Generate(AcmeKeyAlgorithm.ES256);
        var jws = AcmeJws.Sign(key, "https://acme.test/new-order", "nonce-2", includeJwk: false, kid: "https://acme.test/acct/1", "cGF5bG9hZA");

        using var doc = JsonDocument.Parse(jws);
        var protectedJson = Encoding.UTF8.GetString(Base64UrlDecode(doc.RootElement.GetProperty("protected").GetString()!));
        using var headerDoc = JsonDocument.Parse(protectedJson);
        var header = headerDoc.RootElement;

        Assert.Equal("https://acme.test/acct/1", header.GetProperty("kid").GetString());
        Assert.False(header.TryGetProperty("jwk", out _));
    }

    [Fact]
    public void BuildExternalAccountBinding_VerifiesWithHmac()
    {
        using var accountKey = AcmeKey.Generate(AcmeKeyAlgorithm.ES256);
        var hmacKey = RandomNumberGenerator.GetBytes(32);
        var eab = AcmeJws.BuildExternalAccountBinding(accountKey, "eab-kid-1", Convert.ToBase64String(hmacKey), "https://acme.test/new-account");

        using var doc = JsonDocument.Parse(eab);
        var root = doc.RootElement;
        var protectedB64 = root.GetProperty("protected").GetString()!;
        var payload = root.GetProperty("payload").GetString()!;
        var signature = Base64UrlDecode(root.GetProperty("signature").GetString()!);

        var protectedJson = Encoding.UTF8.GetString(Base64UrlDecode(protectedB64));
        using var headerDoc = JsonDocument.Parse(protectedJson);
        var header = headerDoc.RootElement;

        Assert.Equal("HS256", header.GetProperty("alg").GetString());
        Assert.Equal("eab-kid-1", header.GetProperty("kid").GetString());
        Assert.Equal("https://acme.test/new-account", header.GetProperty("url").GetString());
        Assert.Equal(accountKey.GetJwkCanonicalJson(), header.GetProperty("jwk").GetRawText());

        // payload = base64url(account key JWK thumbprint)
        Assert.Equal(accountKey.GetJwkThumbprint(), Encoding.UTF8.GetString(Base64UrlDecode(payload)));

        // 签名 = HMAC-SHA256(key, ASCII(protected "." payload))
        var signingInput = Encoding.ASCII.GetBytes(protectedB64 + "." + payload);
        var expected = HMACSHA256.HashData(hmacKey, signingInput);
        Assert.Equal(expected, signature);
    }

    [Fact]
    public void BuildExternalAccountBinding_AcceptsRawAndBase64UrlHmacKeys()
    {
        using var accountKey = AcmeKey.Generate(AcmeKeyAlgorithm.ES256);

        // base64url 编码（无填充）
        var hmacKey1 = RandomNumberGenerator.GetBytes(32);
        var base64UrlKey = Convert.ToBase64String(hmacKey1).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        AssertEabSignatureMatches(accountKey, base64UrlKey, hmacKey1);

        // 标准 base64（带 = 填充）
        var hmacKey2 = RandomNumberGenerator.GetBytes(32);
        AssertEabSignatureMatches(accountKey, Convert.ToBase64String(hmacKey2), hmacKey2);

        // 原始字节：仅 ASCII 字符串可经 UTF-8 无损往返，且含非 base64 字符强制走 raw 分支
        const string rawKey = "pre-shared-!@#$%^&*()_+secret";
        AssertEabSignatureMatches(accountKey, rawKey, Encoding.UTF8.GetBytes(rawKey));
    }

    private static void AssertEabSignatureMatches(AcmeKey accountKey, string encodedKey, byte[] expectedHmacKey)
    {
        var (signingInput, signature) = ParseEabSignature(accountKey, encodedKey);
        var expected = HMACSHA256.HashData(expectedHmacKey, signingInput);
        Assert.Equal(expected, signature);
    }

    private static (byte[] SigningInput, byte[] Signature) ParseEabSignature(AcmeKey accountKey, string hmacKey)
    {
        var eab = AcmeJws.BuildExternalAccountBinding(accountKey, "kid", hmacKey, "https://acme.test/new-account");
        using var doc = JsonDocument.Parse(eab);
        var root = doc.RootElement;
        var protectedB64 = root.GetProperty("protected").GetString()!;
        var payload = root.GetProperty("payload").GetString()!;
        return (Encoding.ASCII.GetBytes(protectedB64 + "." + payload), Base64UrlDecode(root.GetProperty("signature").GetString()!));
    }

    private static byte[] Base64UrlDecode(string value)
    {
        value = value.Replace('-', '+').Replace('_', '/');
        while (value.Length % 4 != 0)
        {
            value += "=";
        }

        return Convert.FromBase64String(value);
    }
}
