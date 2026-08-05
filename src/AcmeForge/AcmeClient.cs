using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using AcmeForge.Resources;

namespace AcmeForge;

/// <summary>已知 ACME CA 的 directory 端点。</summary>
public static class AcmeEndpoints
{
    /// <summary>Let's Encrypt 生产。</summary>
    public const string LetsEncrypt = "https://acme-v02.api.letsencrypt.org/directory";

    /// <summary>Let's Encrypt 预发（测试签发，证书不受信任）。</summary>
    public const string LetsEncryptStaging = "https://acme-staging-v02.api.letsencrypt.org/directory";

    /// <summary>ZeroSSL（注册账户需 EabCredentials）。</summary>
    public const string ZeroSsl = "https://acme.zerossl.com/v2/DV90";
}

/// <summary>
/// 原生 AOT 兼容的 ACME (RFC 8555) 客户端。
/// 纯 BCL 实现：JWS 签名、nonce 管理、badNonce 重试、EAB、订单/授权/挑战/签发/吊销全流程。
/// </summary>
public sealed class AcmeClient : IDisposable
{
    private const int MaxRequestRetries = 20;
    private const string UserAgent = "AcmeForge/0.1.0";

    private readonly HttpClient _http;
    private readonly bool _ownsHttp;
    private readonly Uri _directoryUrl;
    private readonly AcmeKey _accountKey;
    private readonly object _sync = new();

    private AcmeDirectory? _directory;
    private string? _kid;
    private string? _nonce;
    private bool _disposed;

    /// <summary>
    /// 创建 Let's Encrypt 客户端（自建 HttpClient）。
    /// </summary>
    public static AcmeClient CreateLetsEncrypt(AcmeKey accountKey)
        => new(new Uri(AcmeEndpoints.LetsEncrypt), accountKey);

    /// <summary>
    /// 创建 Let's Encrypt 预发客户端（自建 HttpClient，测试签发，证书不受信任）。
    /// </summary>
    public static AcmeClient CreateLetsEncryptStaging(AcmeKey accountKey)
        => new(new Uri(AcmeEndpoints.LetsEncryptStaging), accountKey);

    /// <summary>
    /// 创建 ZeroSSL 客户端（自建 HttpClient）。注册账户需 EabCredentials，见 <see cref="NewAccountAsync"/>。
    /// </summary>
    public static AcmeClient CreateZeroSsl(AcmeKey accountKey)
        => new(new Uri(AcmeEndpoints.ZeroSsl), accountKey);

    /// <summary>
    /// 创建 ACME 客户端（自建 HttpClient，通常场景用这个即可，无需关心 HTTP 细节）。
    /// </summary>
    /// <param name="directoryUrl">ACME directory 端点，可用 <see cref="AcmeEndpoints"/> 或自定义 CA。</param>
    /// <param name="accountKey">账户密钥。已存在账户用 FromPem 导入，新账户用 Generate 生成。</param>
    public AcmeClient(Uri directoryUrl, AcmeKey accountKey)
        : this(CreateDefaultHttpClient(), ownsHttp: true, directoryUrl, accountKey)
    {
    }

    /// <summary>
    /// 创建 ACME 客户端（自定义 HttpClient，适用于 IHttpClientFactory / DI 环境）。
    /// </summary>
    /// <param name="httpClient">用于 ACME 请求的 HttpClient（建议由 IHttpClientFactory 创建）。</param>
    /// <param name="directoryUrl">ACME directory 端点，可用 <see cref="AcmeEndpoints"/> 或自定义 CA。</param>
    /// <param name="accountKey">账户密钥。已存在账户用 FromPem 导入，新账户用 Generate 生成。</param>
    public AcmeClient(HttpClient httpClient, Uri directoryUrl, AcmeKey accountKey)
        : this(httpClient, ownsHttp: false, directoryUrl, accountKey)
    {
    }

    /// <summary>
    /// 创建 ACME 客户端（自定义 directory + 自定义 HttpClient，顺序为 directory 在前，语义同 <see cref="AcmeClient(HttpClient, Uri, AcmeKey)"/>）。
    /// </summary>
    /// <param name="directoryUrl">ACME directory 端点，可用 <see cref="AcmeEndpoints"/> 或自定义 CA。</param>
    /// <param name="httpClient">用于 ACME 请求的 HttpClient（建议由 IHttpClientFactory 创建）。</param>
    /// <param name="accountKey">账户密钥。已存在账户用 FromPem 导入，新账户用 Generate 生成。</param>
    public AcmeClient(Uri directoryUrl, HttpClient httpClient, AcmeKey accountKey)
        : this(httpClient, ownsHttp: false, directoryUrl, accountKey)
    {
    }

    private AcmeClient(HttpClient httpClient, bool ownsHttp, Uri directoryUrl, AcmeKey accountKey)
    {
        _http = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _ownsHttp = ownsHttp;
        _directoryUrl = directoryUrl ?? throw new ArgumentNullException(nameof(directoryUrl));
        _accountKey = accountKey ?? throw new ArgumentNullException(nameof(accountKey));
    }

    private static HttpClient CreateDefaultHttpClient()
    {
        var http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);
        return http;
    }

    /// <summary>已注册账户的 KID（account URL）。NewAccountAsync 成功后自动设置。</summary>
    public string? Kid => _kid;

    /// <summary>ACME directory 端点。</summary>
    public Uri DirectoryUrl => _directoryUrl;

    /// <summary>获取 ACME directory（内部缓存）。</summary>
    public async Task<AcmeDirectory> GetDirectoryAsync(CancellationToken cancellationToken = default)
    {
        lock (_sync)
        {
            if (_directory is not null)
            {
                return _directory;
            }
        }

        using var request = new HttpRequestMessage(HttpMethod.Get, _directoryUrl);
        using var response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        CaptureNonce(response);

        var json = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        var directory = Deserialize<AcmeDirectory>(json)
            ?? throw new AcmeException("无法解析 ACME directory 响应", httpStatus: (int)response.StatusCode);

        lock (_sync)
        {
            _directory ??= directory;
        }

        return _directory;
    }

    /// <summary>创建（或更新）ACME 账户。成功后客户端自动保存 KID。</summary>
    public async Task<AcmeAccount> NewAccountAsync(
        string[] contacts,
        bool termsOfServiceAgreed,
        EabCredentials? eab = null,
        CancellationToken cancellationToken = default)
    {
        var directory = await GetDirectoryAsync(cancellationToken).ConfigureAwait(false);
        var newAccountUrl = directory.NewAccount
            ?? throw new AcmeException("directory 未提供 newAccount 端点");

        var payload = BuildPayload(w =>
        {
            w.WriteStartObject();
            if (contacts is { Length: > 0 })
            {
                w.WriteStartArray("contact");
                foreach (var contact in contacts)
                {
                    w.WriteStringValue(contact);
                }

                w.WriteEndArray();
            }

            w.WriteBoolean("termsOfServiceAgreed", termsOfServiceAgreed);
            w.WriteBoolean("onlyReturnExisting", false);
            if (eab is not null)
            {
                w.WritePropertyName("externalAccountBinding");
                w.WriteRawValue(AcmeJws.BuildExternalAccountBinding(_accountKey, eab.KeyId, eab.HmacKey, newAccountUrl), skipInputValidation: true);
            }

            w.WriteEndObject();
        });

        var (json, location, _) = await PostJwsAsync(
            newAccountUrl,
            payload,
            includeJwk: true,
            kid: null,
            cancellationToken).ConfigureAwait(false);

        if (!string.IsNullOrWhiteSpace(location))
        {
            lock (_sync)
            {
                _kid = location;
            }
        }

        return Deserialize<AcmeAccount>(json)
            ?? throw new AcmeException("无法解析账户响应");
    }

    /// <summary>获取当前账户信息（POST-as-GET 到 KID URL）。</summary>
    public async Task<AcmeAccount> GetAccountAsync(CancellationToken cancellationToken = default)
    {
        var kid = GetKidOrThrow();
        var (json, _, _) = await PostJwsAsync(kid, string.Empty, includeJwk: false, kid: kid, cancellationToken).ConfigureAwait(false);
        return Deserialize<AcmeAccount>(json) ?? throw new AcmeException("无法解析账户响应");
    }

    /// <summary>创建新证书订单。</summary>
    public async Task<AcmeOrder> NewOrderAsync(IReadOnlyList<string> domains, CancellationToken cancellationToken = default)
    {
        var directory = await GetDirectoryAsync(cancellationToken).ConfigureAwait(false);
        var newOrderUrl = directory.NewOrder
            ?? throw new AcmeException("directory 未提供 newOrder 端点");

        var payload = BuildPayload(w =>
        {
            w.WriteStartObject();
            w.WriteStartArray("identifiers");
            foreach (var domain in domains)
            {
                w.WriteStartObject();
                w.WriteString("type", "dns");
                w.WriteString("value", domain);
                w.WriteEndObject();
            }

            w.WriteEndArray();
            w.WriteEndObject();
        });

        var (json, location, _) = await PostJwsAsync(
            newOrderUrl,
            payload,
            includeJwk: false,
            kid: GetKidOrThrow(),
            cancellationToken).ConfigureAwait(false);

        var order = Deserialize<AcmeOrder>(json) ?? throw new AcmeException("无法解析订单响应");
        if (!string.IsNullOrWhiteSpace(location))
        {
            _lastOrderUrl = location;
        }

        return order;
    }

    private string? _lastOrderUrl;

    /// <summary>最近一次创建的订单 URL（acme_order.location 持久化用）。</summary>
    public string? LastOrderUrl => _lastOrderUrl;

    /// <summary>获取订单资源。</summary>
    public async Task<AcmeOrder> GetOrderAsync(Uri orderUrl, CancellationToken cancellationToken = default)
    {
        var (json, _, _) = await PostAsGetAsync(orderUrl.AbsoluteUri, cancellationToken).ConfigureAwait(false);
        return Deserialize<AcmeOrder>(json) ?? throw new AcmeException("无法解析订单响应");
    }

    /// <summary>获取授权资源。</summary>
    public async Task<AcmeAuthorization> GetAuthorizationAsync(Uri authorizationUrl, CancellationToken cancellationToken = default)
    {
        var (json, _, _) = await PostAsGetAsync(authorizationUrl.AbsoluteUri, cancellationToken).ConfigureAwait(false);
        return Deserialize<AcmeAuthorization>(json) ?? throw new AcmeException("无法解析授权响应");
    }

    /// <summary>获取挑战资源。</summary>
    public async Task<AcmeChallenge> GetChallengeAsync(Uri challengeUrl, CancellationToken cancellationToken = default)
    {
        var (json, _, _) = await PostAsGetAsync(challengeUrl.AbsoluteUri, cancellationToken).ConfigureAwait(false);
        return Deserialize<AcmeChallenge>(json) ?? throw new AcmeException("无法解析挑战响应");
    }

    /// <summary>触发挑战验证（RFC 8555 §7.5.1：POST 空对象 {}，空 payload 会被当作 POST-as-GET 而不触发）。</summary>
    public async Task<AcmeChallenge> ValidateChallengeAsync(Uri challengeUrl, CancellationToken cancellationToken = default)
    {
        var payload = Base64UrlText.Encode("{}"u8);
        var (json, _, _) = await PostJwsAsync(
            challengeUrl.AbsoluteUri,
            payload,
            includeJwk: false,
            kid: GetKidOrThrow(),
            cancellationToken).ConfigureAwait(false);
        return Deserialize<AcmeChallenge>(json) ?? throw new AcmeException("无法解析挑战响应");
    }

    /// <summary>提交 CSR 完成订单（finalize）。</summary>
    public async Task<AcmeOrder> FinalizeAsync(Uri finalizeUrl, byte[] csrDer, CancellationToken cancellationToken = default)
    {
        var payload = BuildPayload(w =>
        {
            w.WriteStartObject();
            w.WriteString("csr", Base64UrlText.Encode(csrDer));
            w.WriteEndObject();
        });

        var (json, _, _) = await PostJwsAsync(
            finalizeUrl.AbsoluteUri,
            payload,
            includeJwk: false,
            kid: GetKidOrThrow(),
            cancellationToken).ConfigureAwait(false);
        return Deserialize<AcmeOrder>(json) ?? throw new AcmeException("无法解析订单响应");
    }

    /// <summary>下载证书 PEM 链（RFC 8555 §7.4.2，使用签名的 POST-as-GET）。</summary>
    public async Task<string> DownloadCertificatePemAsync(Uri certificateUrl, CancellationToken cancellationToken = default)
    {
        var (json, _, _) = await PostAsGetAsync(certificateUrl.AbsoluteUri, cancellationToken).ConfigureAwait(false);
        return json;
    }

    /// <summary>
    /// 下载证书并组装完整成果（链/叶子/私钥 PEM + PFX 导出）。
    /// 注意：返回结果接管 certificateKey 的所有权，用完需 Dispose。
    /// </summary>
    public async Task<AcmeCertificateResult> DownloadCertificateAsync(
        Uri certificateUrl,
        AcmeKey certificateKey,
        CancellationToken cancellationToken = default)
    {
        var chainPem = await DownloadCertificatePemAsync(certificateUrl, cancellationToken).ConfigureAwait(false);
        return AcmeCertificateResult.FromPem(chainPem, certificateKey);
    }

    /// <summary>吊销证书。传 certificateKey 时用证书密钥签名，否则用账户密钥签名。</summary>
    public async Task RevokeCertificateAsync(
        byte[] certificateDer,
        AcmeRevocationReason reason,
        AcmeKey? certificateKey = null,
        CancellationToken cancellationToken = default)
    {
        var directory = await GetDirectoryAsync(cancellationToken).ConfigureAwait(false);
        var revokeUrl = directory.RevokeCert
            ?? throw new AcmeException("directory 未提供 revokeCert 端点");

        var payload = BuildPayload(w =>
        {
            w.WriteStartObject();
            w.WriteString("certificate", Base64UrlText.Encode(certificateDer));
            w.WriteNumber("reason", (int)reason);
            w.WriteEndObject();
        });

        if (certificateKey is not null)
        {
            await PostJwsAsync(revokeUrl, payload, includeJwk: true, kid: null, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            await PostJwsAsync(revokeUrl, payload, includeJwk: false, kid: GetKidOrThrow(), cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// 触发挑战验证并轮询直到结果为 valid/invalid，或超时返回当前状态。
    /// </summary>
    /// <param name="challengeUrl">挑战 URL。</param>
    /// <param name="timeout">总等待超时。</param>
    /// <param name="pollInterval">轮询间隔，默认 3 秒。</param>
    public async Task<AcmeChallenge> WaitForChallengeValidAsync(
        Uri challengeUrl,
        TimeSpan timeout,
        TimeSpan? pollInterval = null,
        CancellationToken cancellationToken = default)
    {
        var interval = pollInterval ?? TimeSpan.FromSeconds(3);
        var deadline = DateTime.UtcNow + timeout;

        await ValidateChallengeAsync(challengeUrl, cancellationToken).ConfigureAwait(false);

        while (true)
        {
            await Task.Delay(interval, cancellationToken).ConfigureAwait(false);

            var challenge = await GetChallengeAsync(challengeUrl, cancellationToken).ConfigureAwait(false);
            var status = challenge.Status?.ToLowerInvariant();
            if (status == "valid" || status == "invalid")
            {
                return challenge;
            }

            if (DateTime.UtcNow >= deadline)
            {
                return challenge;
            }
        }
    }

    /// <summary>
    /// 完成订单：提交 CSR finalize，轮询直到 valid/invalid 或超时；valid 时下载证书 PEM。
    /// </summary>
    /// <param name="orderUrl">订单 URL。</param>
    /// <param name="csrDer">CSR（DER 编码）。</param>
    /// <param name="timeout">总等待超时。</param>
    /// <param name="pollInterval">轮询间隔，默认 2 秒。</param>
    public async Task<AcmeOrderCompletionResult> CompleteOrderAsync(
        Uri orderUrl,
        byte[] csrDer,
        TimeSpan timeout,
        TimeSpan? pollInterval = null,
        CancellationToken cancellationToken = default)
    {
        var interval = pollInterval ?? TimeSpan.FromSeconds(2);
        var deadline = DateTime.UtcNow + timeout;

        var order = await GetOrderAsync(orderUrl, cancellationToken).ConfigureAwait(false);
        var status = order.Status?.ToLowerInvariant();

        // 已经是 valid 的订单直接下载（例如刚验证完成或幂等重试）
        if (status == "valid")
        {
            var certificatePem = await DownloadCertificatePemAsync(
                new Uri(order.Certificate ?? throw new AcmeException("订单 valid 但缺少 certificate 端点")),
                cancellationToken).ConfigureAwait(false);

            return new AcmeOrderCompletionResult
            {
                Status = "valid",
                CertificatePem = certificatePem
            };
        }

        // 需要 finalize
        if (status == "ready")
        {
            await FinalizeAsync(new Uri(order.Finalize ?? throw new AcmeException("订单 ready 但缺少 finalize 端点")), csrDer, cancellationToken).ConfigureAwait(false);
        }

        while (true)
        {
            await Task.Delay(interval, cancellationToken).ConfigureAwait(false);

            var current = await GetOrderAsync(orderUrl, cancellationToken).ConfigureAwait(false);
            var currentStatus = current.Status?.ToLowerInvariant();

            if (currentStatus == "valid")
            {
                var certificatePem = await DownloadCertificatePemAsync(
                    new Uri(current.Certificate ?? throw new AcmeException("订单 valid 但缺少 certificate 端点")),
                    cancellationToken).ConfigureAwait(false);

                return new AcmeOrderCompletionResult
                {
                    Status = "valid",
                    CertificatePem = certificatePem
                };
            }

            if (currentStatus == "invalid")
            {
                return new AcmeOrderCompletionResult
                {
                    Status = "invalid",
                    Error = current.Error
                };
            }

            if (DateTime.UtcNow >= deadline)
            {
                return new AcmeOrderCompletionResult
                {
                    Status = currentStatus,
                    TimedOut = true
                };
            }
        }
    }

    private string GetKidOrThrow() => _kid
        ?? throw new AcmeException("账户尚未注册，无法执行该操作。请先调用 NewAccountAsync");

    private async Task<(string Json, string? Location, string? Nonce)> PostAsGetAsync(string url, CancellationToken cancellationToken)
        => await PostJwsAsync(url, string.Empty, includeJwk: false, kid: GetKidOrThrow(), cancellationToken).ConfigureAwait(false);

    private async Task<(string Json, string? Location, string? Nonce)> PostJwsAsync(
        string url,
        string payload,
        bool includeJwk,
        string? kid,
        CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < MaxRequestRetries; attempt++)
        {
            var nonce = await GetNonceAsync(cancellationToken).ConfigureAwait(false);
            var body = AcmeJws.Sign(_accountKey, url, nonce, includeJwk, kid, payload);

            using var request = new HttpRequestMessage(HttpMethod.Post, url);
            // JWS 的 Content-Type 必须严格为 application/jose+json，不能带 charset 参数（LE 严格校验）。
            // StringContent 会追加 charset=utf-8，故改用 ByteArrayContent。
            request.Content = new ByteArrayContent(Encoding.UTF8.GetBytes(body));
            request.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/jose+json");

            using var response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
            var responseNonce = CaptureNonce(response);
            var json = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            var location = response.Headers.Location?.ToString();

            if (response.IsSuccessStatusCode)
            {
                return (json, location, responseNonce);
            }

            // 503 服务过载：按 Retry-After 等待后重试（同 acme.sh 行为）。
            if (response.StatusCode == HttpStatusCode.ServiceUnavailable)
            {
                var delay = response.Headers.RetryAfter?.Delta ?? TimeSpan.FromSeconds(5);
                if (delay <= TimeSpan.FromSeconds(600))
                {
                    await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
                    continue;
                }
            }

            var problem = TryParseProblem(json);
            if (problem is not null && string.Equals(problem.Type, AcmeErrorTypes.BadNonce, StringComparison.Ordinal))
            {
                // badNonce：nonce 失效，重取重试
                lock (_sync)
                {
                    _nonce = null;
                }

                continue;
            }

            var message = problem?.Detail ?? $"ACME 请求失败 (HTTP {(int)response.StatusCode})";
            if (problem is not null &&
                string.Equals(problem.Type, AcmeErrorTypes.ExternalAccountRequired, StringComparison.Ordinal))
            {
                message += "。该 CA（如 ZeroSSL）要求 EAB 凭据：请在 NewAccountAsync 传入 EabCredentials（KID + HMAC key）。";
            }

            throw new AcmeException(
                message,
                errorType: problem?.Type,
                detail: problem?.Detail,
                httpStatus: (int)response.StatusCode);
        }

        throw new AcmeException("ACME 请求多次重试后仍失败", errorType: AcmeErrorTypes.BadNonce);
    }

    private async Task<string> GetNonceAsync(CancellationToken cancellationToken)
    {
        lock (_sync)
        {
            if (_nonce is not null)
            {
                return _nonce;
            }
        }

        var directory = await GetDirectoryAsync(cancellationToken).ConfigureAwait(false);
        var newNonceUrl = directory.NewNonce
            ?? throw new AcmeException("directory 未提供 newNonce 端点");

        using var request = new HttpRequestMessage(HttpMethod.Head, newNonceUrl);
        using var response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        return CaptureNonce(response)
            ?? throw new AcmeException("newNonce 响应缺少 Replay-Nonce 头");
    }

    private string? CaptureNonce(HttpResponseMessage response)
    {
        var nonce = response.Headers.TryGetValues("Replay-Nonce", out var values)
            ? values.FirstOrDefault()
            : null;

        if (!string.IsNullOrWhiteSpace(nonce))
        {
            lock (_sync)
            {
                _nonce = nonce;
            }
        }

        return nonce;
    }

    private static string BuildPayload(Action<Utf8JsonWriter> write)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            write(writer);
        }

        return Base64UrlText.Encode(buffer.ToArray());
    }

    private static AcmeProblem? TryParseProblem(string json)
    {
        try
        {
            return JsonSerializer.Deserialize(json, AcmeJsonContext.Instance.AcmeProblem);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static T? Deserialize<T>(string json)
    {
        return JsonSerializer.Deserialize(json, GetTypeInfo<T>());
    }

    private static JsonTypeInfo<T> GetTypeInfo<T>()
    {
        if (typeof(T) == typeof(AcmeDirectory))
        {
            return (JsonTypeInfo<T>)(object)AcmeJsonContext.Instance.AcmeDirectory;
        }

        if (typeof(T) == typeof(AcmeAccount))
        {
            return (JsonTypeInfo<T>)(object)AcmeJsonContext.Instance.AcmeAccount;
        }

        if (typeof(T) == typeof(AcmeOrder))
        {
            return (JsonTypeInfo<T>)(object)AcmeJsonContext.Instance.AcmeOrder;
        }

        if (typeof(T) == typeof(AcmeAuthorization))
        {
            return (JsonTypeInfo<T>)(object)AcmeJsonContext.Instance.AcmeAuthorization;
        }

        if (typeof(T) == typeof(AcmeChallenge))
        {
            return (JsonTypeInfo<T>)(object)AcmeJsonContext.Instance.AcmeChallenge;
        }

        throw new NotSupportedException($"不支持的序列化类型: {typeof(T)}");
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        if (_ownsHttp)
        {
            _http.Dispose();
        }

        _accountKey.Dispose();
    }
}
