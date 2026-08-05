using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AcmeForge;

/// <summary>CSR 附加信息。</summary>
public sealed class CsrOptions
{
    public string? CountryName { get; set; }
    public string? State { get; set; }
    public string? Locality { get; set; }
    public string? Organization { get; set; }
    public string? OrganizationUnit { get; set; }
}

/// <summary>
/// 生成 PKCS#10 CSR，完整支持多域名 SAN（RFC 5280 Subject Alternative Name）。
/// CN = 首选域名，所有域名均加入 SAN 扩展。
/// </summary>
public static class CsrBuilder
{
    public static byte[] CreateSigningRequestDer(
        AcmeKey key,
        string commonName,
        IEnumerable<string> domains,
        CsrOptions? options = null)
    {
        var domainList = domains
            .Where(d => !string.IsNullOrWhiteSpace(d))
            .Select(d => d.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (domainList.Count == 0)
        {
            throw new ArgumentException("CSR 至少需要一个域名", nameof(domains));
        }

        if (string.IsNullOrWhiteSpace(commonName))
        {
            commonName = domainList[0];
        }

        var subject = new X500DistinguishedName(BuildSubject(commonName, options));

        var ecdsa = key.GetEcDsa();
        var rsa = key.GetRsa();

        CertificateRequest request;
        if (ecdsa is not null)
        {
            request = new CertificateRequest(subject, ecdsa, HashAlgorithmName.SHA256);
        }
        else if (rsa is not null)
        {
            request = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        else
        {
            throw new InvalidOperationException("密钥未初始化");
        }

        // SAN：所有域名必须全部加入 Subject Alternative Name
        var sanBuilder = new SubjectAlternativeNameBuilder();
        foreach (var domain in domainList)
        {
            sanBuilder.AddDnsName(domain);
        }

        request.CertificateExtensions.Add(sanBuilder.Build());
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));

        var keyUsage = ecdsa is not null
            ? X509KeyUsageFlags.DigitalSignature
            : X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment;
        request.CertificateExtensions.Add(new X509KeyUsageExtension(keyUsage, false));

        return request.CreateSigningRequest();
    }

    public static string CreateSigningRequestPem(
        AcmeKey key,
        string commonName,
        IEnumerable<string> domains,
        CsrOptions? options = null)
    {
        var der = CreateSigningRequestDer(key, commonName, domains, options);
        return PemEncoding.WriteString("CERTIFICATE REQUEST", der);
    }

    private static string BuildSubject(string commonName, CsrOptions? options)
    {
        var parts = new List<string> { $"CN={EscapeDistinguishedNameValue(commonName)}" };

        if (!string.IsNullOrWhiteSpace(options?.CountryName))
        {
            parts.Add($"C={EscapeDistinguishedNameValue(options.CountryName!)}");
        }

        if (!string.IsNullOrWhiteSpace(options?.State))
        {
            parts.Add($"ST={EscapeDistinguishedNameValue(options.State!)}");
        }

        if (!string.IsNullOrWhiteSpace(options?.Locality))
        {
            parts.Add($"L={EscapeDistinguishedNameValue(options.Locality!)}");
        }

        if (!string.IsNullOrWhiteSpace(options?.Organization))
        {
            parts.Add($"O={EscapeDistinguishedNameValue(options.Organization!)}");
        }

        if (!string.IsNullOrWhiteSpace(options?.OrganizationUnit))
        {
            parts.Add($"OU={EscapeDistinguishedNameValue(options.OrganizationUnit!)}");
        }

        return string.Join(", ", parts);
    }

    private static string EscapeDistinguishedNameValue(string value)
        => value.Replace("\\", "\\\\").Replace(",", "\\,").Replace("+", "\\+").Replace("\"", "\\\"");
}
