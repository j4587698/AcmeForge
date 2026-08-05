using System.Security.Cryptography.X509Certificates;

namespace AcmeForge;

/// <summary>
/// 一次签发的完整成果：证书链 PEM + 证书私钥，可直接输出 key/chain PEM 或 PFX 流。
/// 持有证书私钥（<see cref="AcmeKey"/>）的所有权，用完需 Dispose。
/// </summary>
public sealed class AcmeCertificateResult : IDisposable
{
    private const string BeginMarker = "-----BEGIN CERTIFICATE-----";
    private const string EndMarker = "-----END CERTIFICATE-----";

    private readonly AcmeKey _certificateKey;

    private AcmeCertificateResult(string chainPem, AcmeKey certificateKey)
    {
        (LeafCertificatePem, IntermediateChainPem) = SplitChain(chainPem);
        FullChainPem = chainPem;
        _certificateKey = certificateKey;
    }

    /// <summary>叶子（服务器）证书 PEM。</summary>
    public string LeafCertificatePem { get; }

    /// <summary>中间证书链 PEM（不含叶子，可能为空）。</summary>
    public string IntermediateChainPem { get; }

    /// <summary>完整链 PEM（叶子 + 中间证书，LE 原始响应）。</summary>
    public string FullChainPem { get; }

    /// <summary>证书私钥 PKCS#8 PEM。</summary>
    public string PrivateKeyPem => _certificateKey.ToPem();

    /// <summary>从 LE 返回的完整链 PEM 与证书密钥组装结果。</summary>
    public static AcmeCertificateResult FromPem(string chainPem, AcmeKey certificateKey)
    {
        if (string.IsNullOrWhiteSpace(chainPem))
        {
            throw new ArgumentException("证书链 PEM 为空", nameof(chainPem));
        }

        if (certificateKey is null)
        {
            throw new ArgumentNullException(nameof(certificateKey));
        }

        return new AcmeCertificateResult(chainPem, certificateKey);
    }

    /// <summary>构造带私钥的证书对象（直接用于 TLS 绑定，调用方负责 Dispose）。</summary>
    public X509Certificate2 BuildCertificateWithPrivateKey()
        => X509Certificate2.CreateFromPem(LeafCertificatePem, PrivateKeyPem);

    /// <summary>导出 PFX 字节流（可带密码），直接落盘或传入反向代理/托管绑定。</summary>
    public byte[] ExportPfx(string? password = null)
    {
        using var certificate = BuildCertificateWithPrivateKey();
        return password is null
            ? certificate.Export(X509ContentType.Pfx)
            : certificate.Export(X509ContentType.Pfx, password);
    }

    public void Dispose() => _certificateKey.Dispose();

    private static (string Leaf, string Intermediate) SplitChain(string chainPem)
    {
        var blocks = new List<string>();
        var index = 0;
        while (index < chainPem.Length)
        {
            var start = chainPem.IndexOf(BeginMarker, index, StringComparison.Ordinal);
            if (start < 0)
            {
                break;
            }

            var end = chainPem.IndexOf(EndMarker, start, StringComparison.Ordinal);
            if (end < 0)
            {
                break;
            }

            end += EndMarker.Length;
            blocks.Add(chainPem[start..end]);
            index = end;
        }

        if (blocks.Count == 0)
        {
            throw new ArgumentException("PEM 中未找到证书块", nameof(chainPem));
        }

        return (blocks[0], string.Join(Environment.NewLine, blocks.Skip(1)));
    }
}
