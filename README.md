# AcmeForge

AcmeForge 是一个原生 AOT 兼容的 ACME (RFC 8555) 客户端库，内置多个 DNS 提供商，用于自动签发与续期 Let's Encrypt 等 CA 的 TLS 证书。纯 .NET BCL 实现，零反射、零第三方加密库依赖，JSON 全量源生成。

AcmeForge is a native AOT compatible ACME (RFC 8555) client library for .NET with built-in DNS providers, used to automatically issue and renew TLS certificates from Let's Encrypt and other CAs. Pure .NET BCL, zero reflection, zero third-party crypto dependencies, fully source-generated JSON.

当前版本：`0.1.0`

## 特性 / Features

- **原生 AOT 兼容**：`IsTrimmable` + `IsAotCompatible`，JSON 全量源生成，无反射，可裁剪（trimmable）
- **零第三方加密依赖**：ECDSA / RSA 密钥、JWS 签名、JWK / 指纹（RFC 7638）全是 BCL 实现
- **完整 ACME 流程**：目录发现、账户注册（含 EAB）、订单、授权、http-01 / dns-01 / tls-alpn-01 挑战、CSR（多 SAN）、签发下载、吊销
- **证书成果一键导出**：链 / 叶子 / 私钥 PEM 与 PFX 字节流，直接落盘或绑定 TLS
- **内置 7 个 DNS 提供商**：Cloudflare、阿里云、腾讯云 DNSPod 3.0、DNSPod 传统 API、Azure、AWS Route 53、GoDaddy
- **域名字面处理规范**：多标签公共后缀感知，正确提取根域名与子域名（如 `co.uk`、`.cn`）

- **Native AOT friendly**: `IsTrimmable` + `IsAotCompatible`, source-generated JSON, reflection-free
- **Zero third-party crypto deps**: ECDSA/RSA keys, JWS signing, JWK/thumbprint (RFC 7638) all built in
- **Full ACME flow**: directory, account (with EAB), order, authorization, http-01 / dns-01 / tls-alpn-01 challenges, multi-SAN CSR, issuance, revocation
- **One-shot artifact export**: fullchain / leaf / private-key PEM and PFX bytes, ready to save or bind
- **7 built-in DNS providers**: Cloudflare, Aliyun, Tencent DNSPod v3, DNSPod traditional API, Azure, AWS Route 53, GoDaddy
- **Correct domain handling**: multi-label public-suffix aware root/sub-domain extraction (e.g. `co.uk`, `.cn`)

## 依赖 / Dependencies

- .NET 10 (`net10.0`)
- `Microsoft.Extensions.Http`、`Microsoft.Extensions.Configuration.Abstractions`

## 快速开始 / Quick Start

```csharp
using AcmeForge;

// 账户密钥：生成新密钥，或用 AcmeKey.FromPem(...) 导入已有 PKCS#8 密钥
using var accountKey = AcmeKey.Generate(AcmeKeyAlgorithm.ES256);
using var httpClient = new HttpClient();

var client = new AcmeClient(
    httpClient,
    new Uri("https://acme-v02.api.letsencrypt.org/directory"),
    accountKey);

// 注册账户（ZeroSSL / Google / SSL.com 需传 EabCredentials）
var account = await client.NewAccountAsync(
    ["mailto:admin@example.com"],
    termsOfServiceAgreed: true);

// 创建订单（支持多域名与通配符：["*.example.com", "example.com"]）
var order = await client.NewOrderAsync(["example.com", "www.example.com"]);
var orderUrl = client.LastOrderUrl; // 持久化，续期时复用账户密钥调用

// 逐个授权验证
foreach (var authzUrl in order.Authorizations ?? [])
{
    var authz = await client.GetAuthorizationAsync(new Uri(authzUrl));
    var challenge = authz.Challenges?.FirstOrDefault(c => c.Type == "http-01");
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

// 方式二：完整成果（证书私钥由结果接管所有权，用完 Dispose）
using var result = await client.DownloadCertificateAsync(new Uri(order.Certificate!), certKey);
File.WriteAllText("server.fullchain.pem", result.FullChainPem);   // 叶子 + 中间链
File.WriteAllText("server.key.pem", result.PrivateKeyPem);        // PKCS#8 私钥
File.WriteAllBytes("server.pfx", result.ExportPfx());             // 或 ExportPfx("密码")
```

## dns-01 挑战 / DNS-01 Challenge

dns-01 无需公网端口。在 `ValidateChallengeAsync` 前，通过任意 `IDnsProvider` 将 `ChallengeHelper.ComputeDnsTxtRecordValue(keyAuthz)` 写入对应域名的 `_acme-challenge` TXT 记录，等待生效后触发验证，验证完成后删除记录。

```csharp
using AcmeForge.Dns;

services.AddHttpClient<CloudflareDnsProvider>(); // 或用容器/手动 new

var provider = ...; // IDnsProvider
var txtValue = ChallengeHelper.ComputeDnsTxtRecordValue(keyAuthz);
await provider.CreateTxtRecordAsync("example.com", "_acme-challenge.example.com", txtValue, creds);
await client.ValidateChallengeAsync(new Uri(challenge.Url!));
// 轮询直至验证通过
await provider.DeleteAllTxtRecordsByNameAsync("example.com", "_acme-challenge.example.com", creds);
```

所有提供商实现 `IDnsProvider`：

- `CreateTxtRecordAsync(domain, recordName, value, credentials)`
- `DeleteTxtRecordAsync(domain, recordName, value, credentials)`
- `DeleteAllTxtRecordsByNameAsync(domain, recordName, credentials)`
- `TestConnectionAsync(credentials)`

### 凭据 / Credentials

凭据以 `IReadOnlyDictionary<string, object?>` 传入；未显式传入时，会回退读取 `IConfiguration` 的 `DnsProviders:{Provider类型}:{键}` 配置项（例如 `DnsProviders:Cloudflare:ApiToken`）。

| Provider（`Name`） | 凭据键 / Credential keys | 说明 / Notes |
|---|---|---|
| Cloudflare（`cloudflare`） | `api_token` | DNS API Token |
| 阿里云 Aliyun（`aliyun`） | `access_key_id`, `access_key_secret` | `DescribeDomains` / `DescribeDomainRecords` |
| 腾讯云 DNSPod v3（`tencent`） | `secret_id` / `secretId`, `secret_key` / `secretKey` | `dnspod.tencentcloudapi.com` |
| DNSPod 传统 API（`dnspod` / `dnspod-traditional`） | `login_token`，或 `secretId` + `secretKey` | `dnsapi.cn` |
| Azure（`azure`） | `clientId`, `clientSecret`, `tenantId`, `subscriptionId`, `resourceGroup` | DNS 区由根域名自动推导 |
| AWS Route 53（`aws`） | `accessKeyId`, `secretAccessKey`，可选 `region` | Route 53 为全局服务，签名与端点固定用 `us-east-1` |
| GoDaddy（`godaddy`） | `api_key` / `apiKey`, `api_secret` / `apiSecret` | 为开发商生成的 Key/Secret |

## 项目结构 / Project Structure

```text
AcmeForge/
├── AcmeForge.sln
├── src/AcmeForge/
│   ├── AcmeClient.cs            # ACME 协议客户端（目录/账户/订单/挑战/签发/吊销）
│   ├── AcmeKey.cs               # ES256/ES384/RS256 密钥：PKCS#8 PEM 导入导出、JWK 指纹
│   ├── AcmeJws.cs               # RFC 7515 JWS / RFC 8555 EAB 签名
│   ├── AcmeCertificateResult.cs # 签发成果：链/叶子/私钥 PEM + PFX 导出
│   ├── ChallengeHelper.cs       # Key Authorization、TXT 值、tls-alpn-01 证书
│   ├── CsrBuilder.cs            # 多 SAN CSR（RFC 5280）
│   ├── Resources/AcmeModels.cs  # ACME 资源 DTO（源生成 JSON）
│   └── Dns/                     # 7 个 DNS 提供商 + IDnsProvider + DnsDomainHelper
└── tests/
    ├── AcmeForge.Tests/         # 单元测试（含 FAKE ACME 服务器、82+ 用例）
    └── ManualSmoke/             # 交互式冒烟：真实 Let's Encrypt staging 签发验证
```

## 构建与测试 / Build & Test

```bash
# 还原并构建
dotnet build AcmeForge.sln -c Release

# 运行全部测试
dotnet test AcmeForge.sln -c Release

# 发布 NuGet 包（GeneratePackageOnBuild 已开启）
dotnet pack src/AcmeForge/AcmeForge.csproj -c Release
```

冒烟测试（需真实 DNS 凭据，使用 LE staging 签发并落盘 fullchain/key/pfx）：

```bash
dotnet run --project tests/ManualSmoke
```

## 发布 / Publishing

版本号维护在 `src/AcmeForge/AcmeForge.csproj` 的 `<Version>`。包名 `AcmeForge`，MIT 许可，源码位于 https://github.com/j4587698/AcmeForge 。

The version lives in `<Version>` in `src/AcmeForge/AcmeForge.csproj`. Package id is `AcmeForge`, MIT licensed, source at https://github.com/j4587698/AcmeForge .

## 许可证 / License

MIT