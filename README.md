# AcmeForge

原生 AOT 兼容的 ACME (RFC 8555) 客户端库，内置 DNS 提供商，用于签发与续期 Let's Encrypt 等 CA 的 TLS 证书。纯 .NET BCL 实现，零反射、零第三方加密依赖。

> Native AOT compatible ACME (RFC 8555) client for .NET with built-in DNS providers. Pure BCL, zero reflection, zero third-party crypto dependencies.

当前版本：`0.1.0`

## 特性

- 原生 AOT 兼容（`IsTrimmable` + `IsAotCompatible`），JSON 全量源生成
- ACME 全流程：账户注册（含 EAB）、订单、授权、http-01 / dns-01 / tls-alpn-01 挑战、多 SAN CSR、签发、吊销
- 证书成果一站式导出：fullchain / 私钥 PEM / PFX 字节流
- 内置 7 个 DNS 提供商：Cloudflare、阿里云、腾讯云 DNSPod v3、DNSPod 传统 API、Azure、AWS Route 53、GoDaddy
- 通配符下单友好：dns-01 记录名正确去 `*.` 前缀，CSR 与订单 identifiers 严格一致

## 快速开始

只需 3 个参数创建客户端：ACME directory、账户密钥。HttpClient 由库内部管理。

```csharp
using AcmeForge;

// 账户密钥：新账户用 Generate，续期用 AcmeKey.FromPem(pem) 导入
using var accountKey = AcmeKey.Generate(AcmeKeyAlgorithm.ES256);

var client = new AcmeClient(
    new Uri("https://acme-v02.api.letsencrypt.org/directory"),
    accountKey);

// 1. 注册账户（ZeroSSL/Google/SSL.com 需传 EabCredentials）
await client.NewAccountAsync(["mailto:admin@example.com"], termsOfServiceAgreed: true);

// 2. 创建订单（支持多域名与通配符）
var order = await client.NewOrderAsync(["example.com", "www.example.com"]);

// 3. 逐个授权验证（http-01 示例）
foreach (var authzUrl in order.Authorizations ?? [])
{
    var authz = await client.GetAuthorizationAsync(new Uri(authzUrl));
    var challenge = authz.Challenges?.FirstOrDefault(c => c.Type == "http-01");
    if (challenge is null) continue;

    var keyAuthz = ChallengeHelper.ComputeKeyAuthorization(challenge.Token!, accountKey);
    // 将 keyAuthz 以文件名 <token> 放到 http://<domain>/.well-known/acme-challenge/
    await client.ValidateChallengeAsync(new Uri(challenge.Url!));
    // 轮询 GetChallengeAsync 直至 Status == "valid"
}

// 4. 提交 CSR 并下载证书
var certKey = AcmeKey.Generate(AcmeKeyAlgorithm.ES256); // 证书私钥，由 DownloadCertificateAsync 结果接管
var csr = CsrBuilder.CreateSigningRequestDer(certKey, "example.com", ["example.com", "www.example.com"]);
order = await client.FinalizeAsync(new Uri(order.Finalize!), csr);
// 轮询 GetOrderAsync 直至 Status == "valid"

using var cert = await client.DownloadCertificateAsync(new Uri(order.Certificate!), certKey);
File.WriteAllText("server.fullchain.pem", cert.FullChainPem);  // 叶子 + 中间链
File.WriteAllText("server.key.pem", cert.PrivateKeyPem);       // PKCS#8 私钥
File.WriteAllBytes("server.pfx", cert.ExportPfx());            // 或 ExportPfx("密码")
```

需要精确控制 HttpClient（超时、代理、连接池）时，可传入自定义实例；此时 HttpClient 的生命周期由调用方负责：

```csharp
using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
var client = new AcmeClient(http, new Uri("https://acme-v02.api.letsencrypt.org/directory"), accountKey);
```

证书成果 `AcmeCertificateResult` 同时提供 `LeafCertificatePem`、`IntermediateChainPem`、`BuildCertificateWithPrivateKey()`（直接用于 TLS 绑定）。

> Full ACME flow in one call chain; the library manages its own `HttpClient` unless you pass one in. Download gives you PEM chain + PKCS#8 key + PFX bytes.

## dns-01 挑战

dns-01 无需公网端口。验证前把 TXT 值写入 `_acme-challenge` 记录，确认生效后触发验证：

```csharp
using AcmeForge.Dns;

var txtValue = ChallengeHelper.ComputeDnsTxtRecordValue(keyAuthz);
await provider.CreateTxtRecordAsync("example.com", "_acme-challenge.example.com", txtValue, creds);
await client.ValidateChallengeAsync(new Uri(challenge.Url!));
// 轮询通过后
await provider.DeleteAllTxtRecordsByNameAsync("example.com", "_acme-challenge.example.com", creds);
```

通配符域名（`*.example.com`）会自动去掉 `*.` 再拼接记录名。

所有提供商实现 `IDnsProvider`：`CreateTxtRecordAsync` / `DeleteTxtRecordAsync` / `DeleteAllTxtRecordsByNameAsync` / `TestConnectionAsync`。

## DNS 提供商

| 提供商 | 凭据键 | 说明 |
|---|---|---|
| Cloudflare | `api_token` | DNS API Token |
| 阿里云 Aliyun | `access_key_id`, `access_key_secret` | |
| 腾讯云 DNSPod v3 | `secret_id`/`secretId`, `secret_key`/`secretKey` | `dnspod.tencentcloudapi.com` |
| DNSPod 传统 API | `login_token` 或 `secretId`+`secretKey` | `dnsapi.cn` |
| Azure | `clientId`, `clientSecret`, `tenantId`, `subscriptionId`, `resourceGroup` | DNS 区由根域名自动推导 |
| AWS Route 53 | `accessKeyId`, `secretAccessKey`（可选 `region`） | 全局服务，签名/端点固定 `us-east-1` |
| GoDaddy | `api_key`/`apiKey`, `api_secret`/`apiSecret` | |

凭据以 `IReadOnlyDictionary<string, object?>` 传入；未传入时回退读取配置项 `DnsProviders:{Provider类型}:{键}`（如 `DnsProviders:Cloudflare:ApiToken`）。

## 项目结构

```text
AcmeForge/
├── AcmeForge.sln
├── src/AcmeForge/
│   ├── AcmeClient.cs            # ACME 协议与流程
│   ├── AcmeKey.cs               # ES256/ES384/RS256：PKCS#8 导入导出、JWK 指纹
│   ├── AcmeCertificateResult.cs # 证书成果：PEM + PFX
│   ├── ChallengeHelper.cs       # Key Authorization、TXT 值
│   ├── CsrBuilder.cs            # 多 SAN CSR
│   ├── Resources/AcmeModels.cs  # DTO（源生成 JSON）
│   └── Dns/                     # IDnsProvider + 7 个提供商 + 域名工具
└── tests/
    ├── AcmeForge.Tests/         # 单测（含 FAKE ACME 服务器）
    └── ManualSmoke/             # 交互式 LE staging 真实签发验证
```

## 构建与测试

```bash
dotnet build AcmeForge.sln -c Release
dotnet test AcmeForge.sln -c Release

# 冒烟测试：真实 LE staging 签发（需要 DNS 凭据）
dotnet run --project tests/ManualSmoke
```

## 许可证

MIT · 源码：https://github.com/j4587698/AcmeForge