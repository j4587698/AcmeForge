using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace AcmeForge;

/// <summary>
/// ACME 挑战验证辅助：Key Authorization、DNS-01 TXT 值、TLS-ALPN-01 验证证书。
/// </summary>
public static class ChallengeHelper
{
    /// <summary>计算 Key Authorization = token + "." + base64url(SHA256(JWK thumbprint))。</summary>
    public static string ComputeKeyAuthorization(string token, AcmeKey accountKey)
        => $"{token}.{accountKey.GetJwkThumbprint()}";

    /// <summary>计算 DNS-01 TXT 记录值 = base64url(SHA256(keyAuthorization))。</summary>
    public static string ComputeDnsTxtRecordValue(string keyAuthorization)
    {
        var hash = SHA256.HashData(Encoding.ASCII.GetBytes(keyAuthorization));
        return Base64UrlText.Encode(hash);
    }

    /// <summary>
    /// 计算 DNS-01 TXT 记录名 = "_acme-challenge." + 域名。
    /// 通配符授权（identifier 为 *.example.com）自动去掉 *. 前缀。
    /// </summary>
    public static string ComputeDnsTxtRecordName(string identifier)
    {
        if (string.IsNullOrWhiteSpace(identifier))
        {
            throw new ArgumentException("identifier 不能为空", nameof(identifier));
        }

        var normalized = identifier.StartsWith("*.", StringComparison.Ordinal) ? identifier[2..] : identifier;
        return $"_acme-challenge.{normalized}";
    }

    /// <summary>计算 TLS-ALPN-01 acmeIdentifier 哈希 = SHA256(keyAuthorization)。</summary>
    public static byte[] ComputeAcmeIdentifierHash(string keyAuthorization)
        => SHA256.HashData(Encoding.ASCII.GetBytes(keyAuthorization));
}

/// <summary>
/// TLS-ALPN-01 (RFC 8737) 验证证书生成。
/// </summary>
public static class TlsAlpnChallengeCertificate
{
    /// <summary>TLS-ALPN-01 ALPN 协议标识。</summary>
    public const string AcmeTlsAlpnProtocol = "acme-tls/1";

    /// <summary>id-pe-acmeIdentifier 扩展 OID。</summary>
    public const string IdPeAcmeIdentifier = "1.3.6.1.5.5.7.1.31";

    /// <summary>id-kp-serverAuth 扩展 OID。</summary>
    public const string IdKpServerAuth = "1.3.6.1.5.5.7.3.1";

    /// <summary>
    /// 生成 TLS-ALPN-01 验证证书（自签名，含 id-pe-acmeIdentifier 扩展）。
    /// </summary>
    public static X509Certificate2 Create(string domain, string keyAuthorization, TimeSpan? lifetime = null)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            throw new ArgumentException("域名不能为空", nameof(domain));
        }

        if (string.IsNullOrWhiteSpace(keyAuthorization))
        {
            throw new ArgumentException("Key Authorization 不能为空", nameof(keyAuthorization));
        }

        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var subject = new X500DistinguishedName($"CN={domain}");
        var acmeIdentifierHash = ChallengeHelper.ComputeAcmeIdentifierHash(keyAuthorization);

        var request = new CertificateRequest(subject, ecdsa, HashAlgorithmName.SHA256);

        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddDnsName(domain);
        request.CertificateExtensions.Add(sanBuilder.Build());

        // RFC 8737: id-pe-acmeIdentifier 扩展必须是 DER 编码的 OCTET STRING
        var derEncoded = new byte[34];
        derEncoded[0] = 0x04; // OCTET STRING tag
        derEncoded[1] = 0x20; // length = 32
        acmeIdentifierHash.CopyTo(derEncoded, 2);
        request.CertificateExtensions.Add(new X509Extension(IdPeAcmeIdentifier, derEncoded, critical: true));

        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new(IdKpServerAuth) }, critical: false));

        var notBefore = DateTimeOffset.UtcNow.AddMinutes(-5);
        var notAfter = DateTimeOffset.UtcNow.Add(lifetime ?? TimeSpan.FromHours(1));

        using var tempCert = request.CreateSelfSigned(notBefore, notAfter);

        // 导出 PFX 再加载，保证私钥独立于原始 ECDSA 对象（Windows TLS 握手需要）
        var pfxBytes = tempCert.Export(X509ContentType.Pfx);
        return X509CertificateLoader.LoadPkcs12(pfxBytes, null, X509KeyStorageFlags.Exportable);
    }
}
