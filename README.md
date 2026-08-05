# AcmeForge

Native AOT compatible ACME (RFC 8555) client for .NET with built-in DNS providers.

- 零反射、零第三方加密库依赖（纯 .NET BCL），`IsTrimmable` + `IsAotCompatible`
- JSON 全量源生成，AOT 安全
- 完整支持多域名 SAN 的 CSR 生成
- 内置 Cloudflare / Aliyun / Tencent / DNSPod / DNSPod Traditional / Azure / AWS Route53 / GoDaddy DNS 提供商

## 快速开始

```csharp
using AcmeForge;

// 生成账户密钥（或 KeyFactory 等价物：AcmeKey.FromPem 导入已有密钥）
using var accountKey = AcmeKey.Generate(AcmeKeyAlgorithm.ES256);
using var httpClient = new HttpClient();

var client = new AcmeClient(
    httpClient,
    new Uri("https://acme-v02.api.letsencrypt.org/directory"),
    accountKey);

// 注册账户（ZeroSSL/Google/SSL.com 需传 EabCredentials）
var account = await client.NewAccountAsync(
    ["mailto:admin@example.com"],
    termsOfServiceAgreed: true);

// 创建订单
var order = await client.NewOrderAsync(["example.com", "www.example.com"]);
var orderUrl = client.LastOrderUrl; // 持久化用

// 逐个授权验证
foreach (var authzUrl in order.Authorizations ?? [])
{
    var authz = await client.GetAuthorizationAsync(new Uri(authzUrl));
    var challenge = authz.Challenges?.First(c => c.Type == "http-01");
    if (challenge is null) continue;

    var keyAuthz = ChallengeHelper.ComputeKeyAuthorization(challenge.Token!, accountKey);
    // 将 keyAuthz 暴露到 http://<domain>/.well-known/acme-challenge/<token>
    await client.ValidateChallengeAsync(new Uri(challenge.Url!));
    // 轮询 GetChallengeAsync 直至 Status == "valid"
}

// 提交 CSR 并下载证书
using var certKey = AcmeKey.Generate(AcmeKeyAlgorithm.ES256);
var csr = CsrBuilder.CreateSigningRequestDer(certKey, "example.com", ["example.com", "www.example.com"]);
order = await client.FinalizeAsync(new Uri(order.Finalize!), csr);
// 轮询 GetOrderAsync 直至 Status == "valid"

// 方式一：仅 PEM 链
var certificatePem = await client.DownloadCertificatePemAsync(new Uri(order.Certificate!));

// 方式二：完整成果（链/叶子/私钥 PEM + PFX，证书私钥由结果接管所有权）
using var result = await client.DownloadCertificateAsync(new Uri(order.Certificate!), certKey);
File.WriteAllText("server.fullchain.pem", result.FullChainPem);   // 叶子 + 中间链
File.WriteAllText("server.key.pem", result.PrivateKeyPem);        // PKCS#8 私钥
File.WriteAllBytes("server.pfx", result.ExportPfx());             // 或 ExportPfx("密码")
```

## DNS 提供商

```csharp
using AcmeForge.Dns;

// 依赖注入方式（IHttpClientFactory）
services.AddHttpClient<CloudflareDnsProvider>();
```

所有提供商实现 `IDnsProvider` 接口：`CreateTxtRecordAsync` / `DeleteTxtRecordAsync` / `DeleteAllTxtRecordsByNameAsync` / `TestConnectionAsync`。

## 许可证

MIT
