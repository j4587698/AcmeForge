using System.Security.Cryptography;
using System.Text;
using AcmeForge;

namespace AcmeForge.Tests;

public class AcmeKeyTests
{
    [Theory]
    [InlineData(AcmeKeyAlgorithm.ES256, "ES256")]
    [InlineData(AcmeKeyAlgorithm.ES384, "ES384")]
    [InlineData(AcmeKeyAlgorithm.RS256, "RS256")]
    public void Generate_SetsJwsAlgorithm(AcmeKeyAlgorithm algorithm, string expected)
    {
        using var key = AcmeKey.Generate(algorithm);
        Assert.Equal(expected, key.JwsAlgorithm);
    }

    [Theory]
    [InlineData(AcmeKeyAlgorithm.ES256)]
    [InlineData(AcmeKeyAlgorithm.ES384)]
    [InlineData(AcmeKeyAlgorithm.RS256)]
    public void PemRoundtrip_PreservesKey(AcmeKeyAlgorithm algorithm)
    {
        using var original = AcmeKey.Generate(algorithm);
        var pem = original.ToPem();
        Assert.Contains("PRIVATE KEY", pem);

        using var imported = AcmeKey.FromPem(pem);
        Assert.Equal(algorithm.ToString(), imported.JwsAlgorithm);
        Assert.Equal(original.GetJwkThumbprint(), imported.GetJwkThumbprint());
    }

    [Theory]
    [InlineData(AcmeKeyAlgorithm.ES256)]
    [InlineData(AcmeKeyAlgorithm.ES384)]
    [InlineData(AcmeKeyAlgorithm.RS256)]
    public void Sign_Verify_Roundtrip(AcmeKeyAlgorithm algorithm)
    {
        using var key = AcmeKey.Generate(algorithm);
        var data = Encoding.UTF8.GetBytes("hello acme");

        var signature = key.Sign(data);
        Assert.True(key.Verify(data, signature));

        data[0] ^= 0xFF;
        Assert.False(key.Verify(data, signature));
    }

    [Fact]
    public void Sign_ES256_Returns64ByteJoseSignature()
    {
        using var key = AcmeKey.Generate(AcmeKeyAlgorithm.ES256);
        var signature = key.Sign(Encoding.UTF8.GetBytes("data"));
        Assert.Equal(64, signature.Length);
    }

    [Fact]
    public void Sign_ES384_Returns96ByteJoseSignature()
    {
        using var key = AcmeKey.Generate(AcmeKeyAlgorithm.ES384);
        var signature = key.Sign(Encoding.UTF8.GetBytes("data"));
        Assert.Equal(96, signature.Length);
    }

    [Fact]
    public void GetJwkCanonicalJson_Rfc7515KnownKey_ProducesExactCanonicalJson()
    {
        // RFC 7515 附录 A.1.1 官方示例密钥（ES256, P-256）
        const string pem = """
            -----BEGIN PRIVATE KEY-----
            MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgjpsQnnGQmL+YBIff
            H1136cspYG6+0iY7X1fCE9+E9LKhRANCAAR/zc4ncPbEXUGDy+5v20t7WAczNXvp
            7xO6z248e9FURcfxRM0bvZt+hyzf7bnuufSzaV1uqQskrYpGIyiFiOWt
            -----END PRIVATE KEY-----
            """;

        using var key = AcmeKey.FromPem(pem);

        const string expected =
            "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\",\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\"}";

        Assert.Equal(expected, key.GetJwkCanonicalJson());

        // RFC 7638 公式：base64url(SHA256(canonical JSON))
        var expectedThumbprint = Base64UrlEncode(SHA256.HashData(Encoding.UTF8.GetBytes(expected)));
        Assert.Equal(expectedThumbprint, key.GetJwkThumbprint());
    }

    [Fact]
    public void GetJwkThumbprint_MatchesRfc7638OfficialRsaVector()
    {
        // RFC 7638 3.1 节官方示例（RSA 公钥规范化 JSON）
        const string canonical =
            "{\"e\":\"AQAB\",\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\"}";

        var thumbprint = Base64UrlEncode(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
        Assert.Equal("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", thumbprint);
    }

    [Fact]
    public void GetJwkCanonicalJson_UsesRfc7638FieldOrder()
    {
        using var ecKey = AcmeKey.Generate(AcmeKeyAlgorithm.ES256);
        using var ecDoc = System.Text.Json.JsonDocument.Parse(ecKey.GetJwkCanonicalJson());
        Assert.Equal("P-256", ecDoc.RootElement.GetProperty("crv").GetString());
        Assert.Equal("EC", ecDoc.RootElement.GetProperty("kty").GetString());
        Assert.Equal(new[] { "crv", "kty", "x", "y" }, ecDoc.RootElement.EnumerateObject().Select(p => p.Name).ToList());

        using var rsaKey = AcmeKey.Generate(AcmeKeyAlgorithm.RS256);
        using var rsaDoc = System.Text.Json.JsonDocument.Parse(rsaKey.GetJwkCanonicalJson());
        Assert.Equal("RSA", rsaDoc.RootElement.GetProperty("kty").GetString());
        Assert.Equal(new[] { "e", "kty", "n" }, rsaDoc.RootElement.EnumerateObject().Select(p => p.Name).ToList());
    }

    [Fact]
    public void FromPem_InvalidPem_Throws()
    {
        Assert.Throws<ArgumentException>(() => AcmeKey.FromPem("not a pem"));
    }

    private static string Base64UrlEncode(byte[] data) => Convert.ToBase64String(data)
        .TrimEnd('=')
        .Replace('+', '-')
        .Replace('/', '_');
}
