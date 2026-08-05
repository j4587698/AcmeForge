using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using AcmeForge;

namespace AcmeForge.Tests;

public class ChallengeHelperTests
{
    [Fact]
    public void ComputeKeyAuthorization_AppendsJwkThumbprint()
    {
        using var key = AcmeKey.Generate(AcmeKeyAlgorithm.ES256);
        var auth = ChallengeHelper.ComputeKeyAuthorization("token123", key);

        Assert.Equal($"token123.{key.GetJwkThumbprint()}", auth);
    }

    [Fact]
    public void ComputeDnsTxtRecordValue_MatchesRfc8555Formula()
    {
        const string keyAuthorization = "token.jwk-thumbprint";
        var expected = Base64UrlEncode(SHA256.HashData(Encoding.ASCII.GetBytes(keyAuthorization)));

        Assert.Equal(expected, ChallengeHelper.ComputeDnsTxtRecordValue(keyAuthorization));
    }

    [Fact]
    public void ComputeAcmeIdentifierHash_IsSha256OfKeyAuthorization()
    {
        const string keyAuthorization = "token.jwk-thumbprint";
        var expected = SHA256.HashData(Encoding.ASCII.GetBytes(keyAuthorization));

        Assert.Equal(expected, ChallengeHelper.ComputeAcmeIdentifierHash(keyAuthorization));
    }

    [Fact]
    public void TlsAlpnChallengeCertificate_ContainsRequiredExtensions()
    {
        using var key = AcmeKey.Generate(AcmeKeyAlgorithm.ES256);
        var keyAuthorization = ChallengeHelper.ComputeKeyAuthorization("token", key);

        using var cert = TlsAlpnChallengeCertificate.Create("example.com", keyAuthorization);

        var acmeIdentifier = cert.Extensions
            .OfType<X509Extension>()
            .SingleOrDefault(e => e.Oid?.Value == TlsAlpnChallengeCertificate.IdPeAcmeIdentifier);

        Assert.NotNull(acmeIdentifier);
        Assert.True(acmeIdentifier!.Critical);

        var expectedHash = ChallengeHelper.ComputeAcmeIdentifierHash(keyAuthorization);
        var derValue = new ReadOnlySpan<byte>(acmeIdentifier.RawData);
        Assert.Equal(0x04, derValue[0]);
        Assert.Equal(0x20, derValue[1]);
        Assert.Equal(expectedHash, derValue.Slice(2).ToArray());
    }

    [Fact]
    public void TlsAlpnChallengeCertificate_HasSanForDomain_AndServerAuthEku()
    {
        using var key = AcmeKey.Generate(AcmeKeyAlgorithm.ES256);
        var keyAuthorization = ChallengeHelper.ComputeKeyAuthorization("token", key);

        using var cert = TlsAlpnChallengeCertificate.Create("example.com", keyAuthorization);

        var san = cert.Extensions
            .OfType<X509SubjectAlternativeNameExtension>()
            .Single();
        Assert.Equal(new[] { "example.com" }, san.EnumerateDnsNames().ToList());

        var eku = cert.Extensions
            .OfType<X509EnhancedKeyUsageExtension>()
            .Single();
        Assert.Contains(eku.EnhancedKeyUsages.Cast<Oid>(), oid => oid.Value == TlsAlpnChallengeCertificate.IdKpServerAuth);
    }

    [Fact]
    public void TlsAlpnChallengeCertificate_CertHasPrivateKey_ForTlsHandshake()
    {
        using var key = AcmeKey.Generate(AcmeKeyAlgorithm.ES256);
        var keyAuthorization = ChallengeHelper.ComputeKeyAuthorization("token", key);

        using var cert = TlsAlpnChallengeCertificate.Create("example.com", keyAuthorization);
        Assert.True(cert.HasPrivateKey);
    }

    [Fact]
    public void TlsAlpnChallengeCertificate_EmptyDomain_Throws()
    {
        using var key = AcmeKey.Generate(AcmeKeyAlgorithm.ES256);
        Assert.Throws<ArgumentException>(() => TlsAlpnChallengeCertificate.Create("", "auth"));
    }

    private static string Base64UrlEncode(byte[] data) => Convert.ToBase64String(data)
        .TrimEnd('=')
        .Replace('+', '-')
        .Replace('/', '_');
}
