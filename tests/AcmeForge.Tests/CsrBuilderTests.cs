using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AcmeForge;

namespace AcmeForge.Tests;

public class CsrBuilderTests
{
    [Theory]
    [InlineData(AcmeKeyAlgorithm.ES256)]
    [InlineData(AcmeKeyAlgorithm.RS256)]
    public void CreateSigningRequestPem_Loadable_And_ContainsSubjectAndSan(AcmeKeyAlgorithm algorithm)
    {
        using var key = AcmeKey.Generate(algorithm);
        var pem = CsrBuilder.CreateSigningRequestPem(key, "example.com", new[] { "example.com", "www.example.com", "api.example.com" });

        var request = CertificateRequest.LoadSigningRequestPem(pem, HashAlgorithmName.SHA256, CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions, RSASignaturePadding.Pkcs1);

        Assert.Contains("CN=example.com", request.SubjectName.Name);

        var sans = CollectSanNames(request);
        Assert.Equal(new[] { "example.com", "www.example.com", "api.example.com" }, sans);
    }

    [Fact]
    public void CreateSigningRequestPem_DefaultCommonName_UsesFirstDomain()
    {
        using var key = AcmeKey.Generate(AcmeKeyAlgorithm.ES256);
        var pem = CsrBuilder.CreateSigningRequestPem(key, null!, new[] { "first.example.com", "second.example.com" });

        var request = CertificateRequest.LoadSigningRequestPem(pem, HashAlgorithmName.SHA256, CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions, RSASignaturePadding.Pkcs1);
        Assert.Contains("CN=first.example.com", request.SubjectName.Name);
    }

    [Fact]
    public void CreateSigningRequestPem_DeduplicatesAndTrimsDomains()
    {
        using var key = AcmeKey.Generate(AcmeKeyAlgorithm.ES256);
        var pem = CsrBuilder.CreateSigningRequestPem(key, "example.com",
            new[] { "example.com", "example.com", " WWW.example.com ", "" });

        var request = CertificateRequest.LoadSigningRequestPem(pem, HashAlgorithmName.SHA256, CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions, RSASignaturePadding.Pkcs1);
        Assert.Equal(new[] { "example.com", "WWW.example.com" }, CollectSanNames(request));
    }

    [Fact]
    public void CreateSigningRequestPem_IncludesOptionalSubjectFields()
    {
        using var key = AcmeKey.Generate(AcmeKeyAlgorithm.ES256);
        var options = new CsrOptions
        {
            CountryName = "CN",
            State = "Beijing",
            Locality = "Haidian",
            Organization = "AcmeForge Ltd",
            OrganizationUnit = "Platform",
        };

        var pem = CsrBuilder.CreateSigningRequestPem(key, "example.com", new[] { "example.com" }, options);
        var request = CertificateRequest.LoadSigningRequestPem(pem, HashAlgorithmName.SHA256, CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions, RSASignaturePadding.Pkcs1);
        var subject = request.SubjectName.Name;

        Assert.Contains("C=CN", subject);
        Assert.True(subject.Contains("S=Beijing") || subject.Contains("ST=Beijing"));
        Assert.Contains("L=Haidian", subject);
        Assert.Contains("O=AcmeForge Ltd", subject);
        Assert.Contains("OU=Platform", subject);
    }

    [Fact]
    public void CreateSigningRequest_NoDomains_Throws()
    {
        using var key = AcmeKey.Generate(AcmeKeyAlgorithm.ES256);
        Assert.Throws<ArgumentException>(() => CsrBuilder.CreateSigningRequestPem(key, "example.com", Array.Empty<string>()));
    }

    private static List<string> CollectSanNames(CertificateRequest request)
    {
        var extension = request.CertificateExtensions
            .OfType<X509SubjectAlternativeNameExtension>()
            .Single();

        var names = new List<string>();
        foreach (var name in extension.EnumerateDnsNames())
        {
            names.Add(name);
        }

        return names;
    }
}
