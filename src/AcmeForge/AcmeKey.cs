using System.Buffers.Text;
using System.Security.Cryptography;

namespace AcmeForge;

/// <summary>
/// ACME 账户/证书密钥算法。
/// </summary>
public enum AcmeKeyAlgorithm
{
    ES256,
    ES384,
    RS256,
}

/// <summary>
/// 供 ACME JWS 签名与 JWK 使用的密钥。
/// 纯 BCL 实现，无第三方加密库依赖，AOT 安全。
/// </summary>
public sealed class AcmeKey : IDisposable
{
    private readonly ECDsa? _ecdsa;
    private readonly RSA? _rsa;
    private readonly AcmeKeyAlgorithm _algorithm;

    private AcmeKey(ECDsa ecdsa, AcmeKeyAlgorithm algorithm)
    {
        _ecdsa = ecdsa;
        _algorithm = algorithm;
    }

    private AcmeKey(RSA rsa, AcmeKeyAlgorithm algorithm)
    {
        _rsa = rsa;
        _algorithm = algorithm;
    }

    /// <summary>生成新密钥。</summary>
    public static AcmeKey Generate(AcmeKeyAlgorithm algorithm) => algorithm switch
    {
        AcmeKeyAlgorithm.ES256 => new AcmeKey(ECDsa.Create(ECCurve.NamedCurves.nistP256), algorithm),
        AcmeKeyAlgorithm.ES384 => new AcmeKey(ECDsa.Create(ECCurve.NamedCurves.nistP384), algorithm),
        AcmeKeyAlgorithm.RS256 => new AcmeKey(RSA.Create(2048), algorithm),
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, null),
    };

    /// <summary>
    /// 从 PEM 导入密钥。支持 PKCS#8("PRIVATE KEY")、RFC 5915("EC PRIVATE KEY")、RFC 3447("RSA PRIVATE KEY")。
    /// 兼容 Certes 导出的 PKCS#8 PEM。
    /// </summary>
    public static AcmeKey FromPem(string pem)
    {
        if (string.IsNullOrWhiteSpace(pem))
        {
            throw new ArgumentException("PEM 内容为空", nameof(pem));
        }

        try
        {
            var ecdsa = ECDsa.Create();
            ecdsa.ImportFromPem(pem);
            var curve = ecdsa.ExportParameters(false).Curve.Oid.Value;
            var algorithm = curve switch
            {
                "1.2.840.10045.3.1.7" => AcmeKeyAlgorithm.ES256, // nistP256
                "1.3.132.0.34" => AcmeKeyAlgorithm.ES384,        // nistP384
                _ => throw new NotSupportedException($"不支持的 EC 曲线 OID: {curve}"),
            };
            return new AcmeKey(ecdsa, algorithm);
        }
        catch (CryptographicException)
        {
            // 不是 EC 密钥，尝试 RSA
        }

        try
        {
            var rsa = RSA.Create();
            rsa.ImportFromPem(pem);
            return new AcmeKey(rsa, AcmeKeyAlgorithm.RS256);
        }
        catch (CryptographicException ex)
        {
            throw new ArgumentException("无法解析 PEM 密钥", nameof(pem), ex);
        }
    }

    /// <summary>以 PKCS#8 PEM 格式导出私钥（兼容 Certes 输出格式）。</summary>
    public string ToPem()
    {
        if (_ecdsa is not null)
        {
            return _ecdsa.ExportPkcs8PrivateKeyPem();
        }

        if (_rsa is not null)
        {
            return _rsa.ExportPkcs8PrivateKeyPem();
        }

        throw new InvalidOperationException("密钥未初始化");
    }

    /// <summary>JWS 签名算法标识。</summary>
    public string JwsAlgorithm => _algorithm switch
    {
        AcmeKeyAlgorithm.ES256 => "ES256",
        AcmeKeyAlgorithm.ES384 => "ES384",
        AcmeKeyAlgorithm.RS256 => "RS256",
        _ => throw new ArgumentOutOfRangeException(),
    };

    /// <summary>底层 EC 密钥（供 CSR 生成使用）。</summary>
    internal ECDsa? GetEcDsa() => _ecdsa;

    /// <summary>底层 RSA 密钥（供 CSR 生成使用）。</summary>
    internal RSA? GetRsa() => _rsa;

    /// <summary>计算 RFC 7638 JWK 指纹（ACME Key Authorization 使用）。</summary>
    public string GetJwkThumbprint()
    {
        using var sha256 = SHA256.Create();
        var hash = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(GetJwkCanonicalJson()));
        return Base64Url.EncodeToString(hash);
    }

    /// <summary>
    /// 以 JOSE 原始格式对数据签名。
    /// ES256/ES384 返回 R||S 固定长度（与 DER 相互转换），RS256 直接返回 PKCS#1 签名。
    /// </summary>
    public byte[] Sign(byte[] data)
    {
        if (_ecdsa is not null)
        {
            var hashAlgorithm = _algorithm == AcmeKeyAlgorithm.ES256 ? HashAlgorithmName.SHA256 : HashAlgorithmName.SHA384;
            var signature = _ecdsa.SignData(data, hashAlgorithm);
            var expectedLength = _algorithm == AcmeKeyAlgorithm.ES256 ? 32 : 48;

            // Windows CNG 直接返回原始 R||S (P1363)；Linux/OpenSSL 返回 DER。统一输出 JOSE 原始格式。
            if (signature.Length == expectedLength * 2)
            {
                return signature;
            }

            return ConvertDerSignatureToJose(signature, expectedLength);
        }

        if (_rsa is not null)
        {
            return _rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        throw new InvalidOperationException("密钥未初始化");
    }

    /// <summary>验证 JOSE 原始格式签名。</summary>
    public bool Verify(byte[] data, byte[] signature)
    {
        if (_ecdsa is not null)
        {
            var hashAlgorithm = _algorithm == AcmeKeyAlgorithm.ES256 ? HashAlgorithmName.SHA256 : HashAlgorithmName.SHA384;
            var expectedLength = _algorithm == AcmeKeyAlgorithm.ES256 ? 32 : 48;
            try
            {
                // 优先尝试原始 R||S（Windows CNG 仅接受该格式），失败则回退 DER（Linux/OpenSSL）。
                if (signature.Length == expectedLength * 2 && _ecdsa.VerifyData(data, signature, hashAlgorithm))
                {
                    return true;
                }

                var der = ConvertJoseSignatureToDer(signature, expectedLength);
                return _ecdsa.VerifyData(data, der, hashAlgorithm);
            }
            catch (CryptographicException)
            {
                return false;
            }
        }

        if (_rsa is not null)
        {
            return _rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        throw new InvalidOperationException("密钥未初始化");
    }

    /// <summary>生成 RFC 7638 规范化 JWK JSON（字段顺序固定）。</summary>
    public string GetJwkCanonicalJson()
    {
        using var buffer = new MemoryStream();
        using (var writer = new System.Text.Json.Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            if (_ecdsa is not null)
            {
                var parameters = _ecdsa.ExportParameters(false);
                writer.WriteString("crv", _algorithm == AcmeKeyAlgorithm.ES256 ? "P-256" : "P-384");
                writer.WriteString("kty", "EC");
                writer.WriteString("x", Base64Url.EncodeToString(parameters.Q.X!));
                writer.WriteString("y", Base64Url.EncodeToString(parameters.Q.Y!));
            }
            else if (_rsa is not null)
            {
                var parameters = _rsa.ExportParameters(false);
                writer.WriteString("e", Base64Url.EncodeToString(ToUnsignedBigEndian(parameters.Exponent!)));
                writer.WriteString("kty", "RSA");
                writer.WriteString("n", Base64Url.EncodeToString(ToUnsignedBigEndian(parameters.Modulus!)));
            }
            else
            {
                throw new InvalidOperationException("密钥未初始化");
            }

            writer.WriteEndObject();
        }

        return System.Text.Encoding.UTF8.GetString(buffer.ToArray());
    }

    private static byte[] ToUnsignedBigEndian(byte[] value)
    {
        int start = 0;
        while (start < value.Length - 1 && value[start] == 0)
        {
            start++;
        }

        return value[start..];
    }

    internal static byte[] ConvertDerSignatureToJose(byte[] der, int expectedLength)
    {
        var reader = new System.Formats.Asn1.AsnReader(der, System.Formats.Asn1.AsnEncodingRules.DER);
        var sequence = reader.ReadSequence();
        var r = sequence.ReadIntegerBytes();
        var s = sequence.ReadIntegerBytes();

        var result = new byte[expectedLength * 2];
        r.Span.CopyTo(result.AsSpan(expectedLength - r.Length, r.Length));
        s.Span.CopyTo(result.AsSpan(result.Length - s.Length, s.Length));
        return result;
    }

    internal static byte[] ConvertJoseSignatureToDer(byte[] jose, int expectedLength)
    {
        if (jose.Length != expectedLength * 2)
        {
            throw new CryptographicException("JOSE 签名长度不正确");
        }

        var r = jose.AsSpan(0, expectedLength).TrimStart((byte)0).ToArray();
        var s = jose.AsSpan(expectedLength, expectedLength).TrimStart((byte)0).ToArray();

        var writer = new System.Formats.Asn1.AsnWriter(System.Formats.Asn1.AsnEncodingRules.DER);
        writer.PushSequence();
        writer.WriteInteger(r);
        writer.WriteInteger(s);
        writer.PopSequence();
        return writer.Encode();
    }

    public void Dispose()
    {
        _ecdsa?.Dispose();
        _rsa?.Dispose();
    }
}