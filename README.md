# AcmeForge

原生 AOT 兼容的 ACME (RFC 8555) 客户端库，内置 7 个 DNS 提供商，用于签发与续期 Let's Encrypt / ZeroSSL 等 CA 的 TLS 证书。纯 .NET BCL 实现，零反射、零第三方加密依赖。

> Native AOT compatible ACME (RFC 8555) client for .NET with built-in DNS providers. Pure BCL, zero reflection, zero third-party crypto dependencies.

当前版本：`0.1.0`

## 特性

- 原生 AOT 兼容（`IsTrimmable` + `IsAotCompatible`），JSON 全量源生成，无反射
- ACME 全流程：账户注册（含 EAB）、订单、授权、http-01 / dns-01 / tls-alpn-01 挑战、多 SAN CSR、签发下载、吊销
- 证书成果一站式导出：fullchain / 叶子 / 私钥 PEM、PFX 字节流、带私钥的 `X509Certificate2`
- 内置 DNS 提供商：Cloudflare、阿里云、腾讯云 DNSPod v3、DNSPod 传统 API、Azure、AWS Route 53、GoDaddy
- 通配符友好：dns-01 记录名自动去 `*.` 前缀，CSR 与订单 identifiers 严格一致

## 快速开始

### 创建客户端

支持 4 种方式，按需选择：

| 方式 | 代码 | 适用场景 |
|---|---|---|
| 主流 CA 工厂（自建 HttpClient） | `AcmeClient.CreateLetsEncrypt(key)` / `CreateLetsEncryptStaging(key)` / `CreateZeroSsl(key)` | 日常签发，无需关心 HTTP 细节 |
| 自建 HttpClient + 默认 CA | `new AcmeClient(new Uri(AcmeEndpoints.LetsEncrypt), key)` | 需要自定义超时/代理/连接池 |
| 自建 HttpClient + 自定义 CA | `new AcmeClient(http, new Uri("https://ca.example/directory"), key)` | 自有 CA / Pebble / 内网 CA |
| DI 注入 HttpClient | `new AcmeClient(httpFactory.CreateClient("acme"), new Uri(AcmeEndpoints.LetsEncrypt), key)` | IHttpClientFactory / ASP.NET Core |

`AcmeEndpoints` 提供内置目录：`LetsEncrypt`、`LetsEncryptStaging`、`ZeroSsl`。自建 HttpClient 时生命周期归调用方；工厂与便捷构造函数由库内部创建并随 `Dispose` 释放。

```csharp
using AcmeForge;

using var accountKey = AcmeKey.Generate(AcmeKeyAlgorithm.ES256); // 续期用 AcmeKey.FromPem(pem) 导入已有密钥
var client = AcmeClient.CreateLetsEncrypt(accountKey);

// 注册账户（ZeroSSL/Google/SSL.com 需传 EabCredentials，见下文）
await client.NewAccountAsync(["mailto:admin@example.com"], termsOfServiceAgreed: true);

// 创建订单（支持多域名与通配符：["*.example.com", "example.com"]）
var order = await client.NewOrderAsync(["example.com", "www.example.com"]);
var orderUrl = client.LastOrderUrl; // 持久化，续期复用
```

### http-01 挑战（需要公网 80 端口）

把 Key Authorization 写到 `http://<域名>/.well-known/acme-challenge/<token>` 即可。以 Nginx/静态目录为例，写文件到 webroot：

```csharp
// 遍历订单的每个授权
foreach (var authzUrl in order.Authorizations ?? [])
{
    var authz = await client.GetAuthorizationAsync(new Uri(authzUrl));
    var challenge = authz.Challenges?.FirstOrDefault(c => c.Type == "http-01");
    if (challenge is null) continue;

    // keyAuthz = token + "." + 账户密钥 JWK 指纹（RFC 8555 §8.1）
    var keyAuthz = ChallengeHelper.ComputeKeyAuthorization(challenge.Token!, accountKey);

    // 1. 让公网可访问：把 keyAuthz 内容写到 /var/www/html/.well-known/acme-challenge/<token>
    var tokenFile = Path.Combine("/var/www/html/.well-known/acme-challenge", challenge.Token!);
    Directory.CreateDirectory(Path.GetDirectoryName(tokenFile)!);
    await File.WriteAllTextAsync(tokenFile, keyAuthz);

    // 2. 触发验证并轮询（valid / invalid / 超时）
    await client.ValidateChallengeAsync(new Uri(challenge.Url!));
    while (true)
    {
        await Task.Delay(TimeSpan.FromSeconds(3));
        var current = await client.GetChallengeAsync(new Uri(challenge.Url!));
        if (current.Status is "valid" or "invalid") break;
    }

    // 3. 删除 token 文件
    File.Delete(tokenFile);
}
```

### dns-01 挑战（无需公网端口，支持通配符）

通过任意 `IDnsProvider` 创建 TXT 记录 → 等待生效 → 触发验证 → 删除记录。TXT 值为 Key Authorization 的 SHA-256 摘要，记录名为 `_acme-challenge.<域名>`：

```csharp
using AcmeForge.Dns;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

// 1. 创建提供商（推荐 DI，见"DNS 提供商"一节；此处以手动方式示例）
var services = new ServiceCollection();
services.AddHttpClient();
services.AddLogging();
services.AddSingleton<IConfiguration>(new ConfigurationBuilder().Build());
using var sp = services.BuildServiceProvider();
var httpFactory = sp.GetRequiredService<IHttpClientFactory>();
var provider = new CloudflareDnsProvider(
    sp.GetRequiredService<ILogger<CloudflareDnsProvider>>(), httpFactory,
    sp.GetRequiredService<IConfiguration>());

// 凭据（也可通过配置 DnsProviders:Cloudflare:ApiToken 提供）
var creds = new Dictionary<string, object?> { ["api_token"] = "你的 Cloudflare API Token" };
await provider.TestConnectionAsync(creds); // 可选：预检凭据

foreach (var authzUrl in order.Authorizations ?? [])
{
    var authz = await client.GetAuthorizationAsync(new Uri(authzUrl));
    var challenge = authz.Challenges?.FirstOrDefault(c => c.Type == "dns-01");
    if (challenge is null) continue;

    var keyAuthz = ChallengeHelper.ComputeKeyAuthorization(challenge.Token!, accountKey);
    var txtValue = ChallengeHelper.ComputeDnsTxtRecordValue(keyAuthz); // b64url(SHA256(keyAuthz))

    // 通配符域名 (*.example.com) 会自动去掉 *. 再拼接记录名
    var recordName = $"_acme-challenge.{authz.Identifier!.Value.TrimStart('*', '.')}";
    await provider.CreateTxtRecordAsync(authz.Identifier.Value, recordName, txtValue, creds);

    // 等待 DNS 生效（公共解析器可见后触发，或固定 sleep 15-30s）
    await Task.Delay(TimeSpan.FromSeconds(20));

    await client.ValidateChallengeAsync(new Uri(challenge.Url!));
    while (true)
    {
        await Task.Delay(TimeSpan.FromSeconds(3));
        var current = await client.GetChallengeAsync(new Uri(challenge.Url!));
        if (current.Status is "valid" or "invalid") break;
    }

    await provider.DeleteAllTxtRecordsByNameAsync(authz.Identifier.Value, recordName, creds);
}
```

### 提交 CSR 并下载证书

```csharp
// 证书私钥（新生成；密钥所有权由 DownloadCertificateAsync 的结果接管）
var certKey = AcmeKey.Generate(AcmeKeyAlgorithm.ES256);

// CSR：CN 与 SAN 必须与订单 identifiers 完全一致（通配符含 * 前缀）
var csr = CsrBuilder.CreateSigningRequestDer(certKey, "example.com", ["example.com", "www.example.com"]);
var finalized = await client.FinalizeAsync(new Uri(order.Finalize!), csr);

// 轮询直至 valid
while (true)
{
    await Task.Delay(TimeSpan.FromSeconds(5));
    order = await client.GetOrderAsync(new Uri(orderUrl));
    if (order.Status is "valid" or "invalid") break;
}

// 下载并导出
using var cert = await client.DownloadCertificateAsync(new Uri(order.Certificate!), certKey);
File.WriteAllText("server.fullchain.pem", cert.FullChainPem); // 叶子 + 中间链
File.WriteAllText("server.key.pem", cert.PrivateKeyPem);      // PKCS#8 私钥
File.WriteAllBytes("server.pfx", cert.ExportPfx());           // 或 ExportPfx("密码")

// 直接用于 TLS 绑定（Kestrel/自定义服务器），用完 Dispose
using var x509 = cert.BuildCertificateWithPrivateKey();
```

`AcmeCertificateResult` 完整成员：`LeafCertificatePem`、`IntermediateChainPem`、`FullChainPem`、`PrivateKeyPem`、`ExportPfx(password?)`、`BuildCertificateWithPrivateKey()`。

## DNS 提供商

所有提供商实现 `IDnsProvider`，构造签名统一为 `(ILogger<T>, IHttpClientFactory, IConfiguration)`，可在 ASP.NET Core 中直接注册：

```csharp
// Program.cs
using AcmeForge.Dns;

builder.Services.AddHttpClient<CloudflareDnsProvider>();
builder.Services.AddHttpClient<AliyunDnsProvider>();
builder.Services.AddHttpClient<TencentDnsProvider>();
builder.Services.AddHttpClient<DnsPodDnsProvider>();
builder.Services.AddHttpClient<DnsPodTraditionalDnsProvider>();
builder.Services.AddHttpClient<AzureDnsProvider>();
builder.Services.AddHttpClient<AwsRoute53DnsProvider>();
builder.Services.AddHttpClient<GoDaddyDnsProvider>();
```

凭据有两种提供方式，字典优先：

```csharp
// 方式一：显式传入（优先级更高）
var creds = new Dictionary<string, object?> { ["api_token"] = "..." };
await provider.CreateTxtRecordAsync("example.com", "_acme-challenge.example.com", "txt-value", creds);

// 方式二：IConfiguration 配置项（appsettings.json / 环境变量 / 用户机密）
// "DnsProviders:Cloudflare:ApiToken": "..."
var result = await provider.CreateTxtRecordAsync("example.com", "_acme-challenge.example.com", "txt-value", null);
```

`IDnsProvider` 接口（返回值均为 `DnsOperationResult { Success, Message, Details, ErrorCode }`）：

| 方法 | 说明 |
|---|---|
| `CreateTxtRecordAsync(domain, recordName, value, credentials)` | 创建 TXT 记录；已存在同名记录则更新值 |
| `DeleteTxtRecordAsync(domain, recordName, value, credentials)` | 删除指定的 TXT 记录 |
| `DeleteAllTxtRecordsByNameAsync(domain, recordName, credentials)` | 删除该记录名下全部 TXT 记录（清理用） |
| `TestConnectionAsync(credentials)` | 预检凭据与 API 连通性 |

### 提供商与凭据对照

| 提供商 | 类 / `Name` | 凭据键 | 说明 |
|---|---|---|---|
| Cloudflare | `CloudflareDnsProvider` / `cloudflare` | `api_token` | API Token（非全局 Key） |
| 阿里云 | `AliyunDnsProvider` / `aliyun` | `access_key_id`, `access_key_secret` | 需要 DNS 权限 |
| 腾讯云 DNSPod v3 | `TencentDnsProvider` / `tencent` | `secret_id`/`secretId`, `secret_key`/`secretKey` | `dnspod.tencentcloudapi.com` |
| DNSPod 传统 API | `DnsPodDnsProvider` / `dnspod` | `secretId` + `secretKey`（拼 `login_token`） | `dnsapi.cn` |
| DNSPod 传统（直接 token） | `DnsPodTraditionalDnsProvider` / `dnspod-traditional` | `login_token` 或 `secretId`+`secretKey` | `dnsapi.cn` |
| Azure | `AzureDnsProvider` / `azure` | `clientId`, `clientSecret`, `tenantId`, `subscriptionId`, `resourceGroup` | DNS 区由根域名自动推导 |
| AWS Route 53 | `AwsRoute53DnsProvider` / `aws` | `accessKeyId`, `secretAccessKey`（可选 `region`） | 全局服务，签名/端点固定 `us-east-1` |
| GoDaddy | `GoDaddyDnsProvider` / `godaddy` | `api_key`/`apiKey`, `api_secret`/`apiSecret` | 开发者区生成的 Key/Secret |

## 账户与续期

```csharp
// 续期：用保存的账户密钥 PEM 与 KID，无需重新注册
using var accountKey = AcmeKey.FromPem(File.ReadAllText("account.key.pem"));
var client = AcmeClient.CreateLetsEncrypt(accountKey);
var order = await client.NewOrderAsync(["example.com"]);
// 之后流程与首次一致（NewOrderAsync 之后不需要再调 NewAccountAsync）
```

账户密钥是签发关键资产，请持久化保存（`AcmeKey.ToPem()` 导出 PKCS#8 PEM）。KID（`client.Kid`）与 directory 一起保存，用于账户存在性校验。

### 使用 ZeroSSL（需要 EAB）

ZeroSSL 要求注册账户时携带 EAB 凭据（KID + HMAC Key，在 ZeroSSL 控制台 Developer 页面生成；支持 base64url / 标准 base64 / 原始字节）。缺少 EAB 时抛出含中文提示的 `AcmeException`：

```csharp
var eab = new EabCredentials(KeyId: "你的 EAB KID", HmacKey: "你的 EAB HMAC Key");
var client = AcmeClient.CreateZeroSsl(accountKey);
await client.NewAccountAsync(["mailto:admin@example.com"], termsOfServiceAgreed: true, eab);
```

EAB 仅在创建新账户时需要；续期不需要。ZeroSSL 要求 contact 邮箱已在其控制台验证。

## 项目结构

```text
AcmeForge/
├── AcmeForge.sln
├── src/AcmeForge/
│   ├── AcmeClient.cs            # ACME 协议与流程、CA 工厂、AcmeEndpoints
│   ├── AcmeKey.cs               # ES256/ES384/RS256：PKCS#8 导入导出、JWK 指纹
│   ├── AcmeCertificateResult.cs # 证书成果：PEM + PFX + X509Certificate2
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