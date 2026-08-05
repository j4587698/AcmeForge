using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using AcmeForge;
using AcmeForge.Dns;
using AcmeForge.Resources;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace ManualSmoke;

/// <summary>
/// AcmeForge 冒烟测试（支持 Native AOT）：
///   dns-01  — 无需任何入站端口，通过 Cloudflare/DNSPod 创建 TXT 记录；
///   http-01 — 需要一个公网可达的 HTTP 端口（默认 80），内置极简 HTTP 服务暴露 token。
/// 向 Let's Encrypt Staging 真实签发证书，走通 AcmeClient + DNS 提供商 + ChallengeHelper + CsrBuilder 全流程。
/// </summary>
public class Program
{
    private const string StagingDirectory = "https://acme-staging-v02.api.letsencrypt.org/directory";

    public static async Task<int> Main(string[] args)
    {
        Console.WriteLine("=== AcmeForge 冒烟测试 (Let's Encrypt Staging) ===");

        var challengeType = ReadChoice("挑战类型", new[] { "dns-01", "http-01" });

        string? providerName = null;
        IReadOnlyDictionary<string, object?>? credentials = null;
        IDnsProvider? provider = null;
        SimpleHttpServer? httpServer = null;
        var tokens = new ConcurrentDictionary<string, string>();

        if (challengeType == "dns-01")
        {
            providerName = ReadChoice("DNS 提供商", new[] { "cloudflare", "dnspod" });
            credentials = ReadCredentials(providerName);
        }
        else
        {
            Console.WriteLine("注意：http-01 需要你的机器公网可达，且指定端口（默认 80）能被 Let's Encrypt 访问。");
            var port = ReadInt("HTTP 监听端口", 80);
            httpServer = new SimpleHttpServer(port, tokens);
            httpServer.Start();
            _ = httpServer.RunAsync();
            await SelfCheckAsync(port, tokens);
            Console.WriteLine($"HTTP 服务已启动: http://0.0.0.0:{port}/.well-known/acme-challenge/{{token}}");
        }

        var domain = ReadNonEmpty("证书域名（如 example.com 或 *.example.com，通配符仅支持 dns-01）");
        var email = ReadNonEmpty("联系邮箱（注册 ACME 账户用）");

        var services = BuildServices();
        await using var scope = services.CreateAsyncScope();
        var logger = scope.ServiceProvider.GetRequiredService<ILogger<Program>>();
        var httpClientFactory = scope.ServiceProvider.GetRequiredService<IHttpClientFactory>();

        var accountKey = LoadOrCreateAccountKey(logger);

        using var acmeClient = new AcmeClient(
            httpClientFactory.CreateClient("acme"),
            new Uri(StagingDirectory),
            accountKey);

        var createdRecords = new List<(string Domain, string RecordName, string Value)>();

        try
        {
            if (providerName is not null)
            {
                provider = scope.ServiceProvider.GetRequiredService<IEnumerable<IDnsProvider>>().First(p => p.Name == providerName);
                Console.WriteLine($"\n[1/6] 测试 {provider.DisplayName} 凭据...");
                var test = await provider.TestConnectionAsync(credentials);
                if (!test.Success)
                {
                    Console.WriteLine($"凭据无效: {test.Message} {test.Details}");
                    return 1;
                }
            }
            else
            {
                Console.WriteLine($"\n[1/6] 使用内置 HTTP 服务处理 http-01 挑战");
            }

            Console.WriteLine("\n[2/6] 准备 ACME 账户密钥...");
            var directory = await acmeClient.GetDirectoryAsync();
            logger.LogInformation("已连接 ACME 目录: {Terms}", directory.Meta?.TermsOfService);

            Console.WriteLine("\n[3/6] 注册 ACME 账户...");
            var account = await acmeClient.NewAccountAsync(new[] { $"mailto:{email}" }, termsOfServiceAgreed: true);
            logger.LogInformation("账户已注册: {Status}, kid={Kid}", account.Status, acmeClient.Kid);

            Console.WriteLine("\n[4/6] 创建订单...");
            var order = await acmeClient.NewOrderAsync(new[] { domain });
            logger.LogInformation("订单创建: status={Status}, authz 数={Count}", order.Status, order.Authorizations?.Length);

            foreach (var authzUrl in order.Authorizations ?? Array.Empty<string>())
            {
                await SolveChallengeAsync(acmeClient, accountKey, challengeType, provider, credentials, tokens, new Uri(authzUrl), createdRecords, logger);
            }

            Console.WriteLine("\n[5/6] 等待订单就绪并提交 CSR...");
            order = await PollOrderAsync(acmeClient, acmeClient.LastOrderUrl!, "ready", TimeSpan.FromSeconds(60), logger);
            if (order.Status != "ready")
            {
                Console.WriteLine($"订单未就绪，终止。错误: {order.Error?.Detail}");
                return 2;
            }

            // 证书密钥所有权交由 DownloadCertificateAsync 的结果接管（result 用完释放）。
            var certKey = AcmeKey.Generate(AcmeKeyAlgorithm.ES256);
            // CSR 必须与订单 identifiers 完全一致（含通配符 * 前缀），LE 会把 CN 也纳入比对（同 acme.sh）。
            var csrDer = CsrBuilder.CreateSigningRequestDer(certKey, domain, new[] { domain });
            var finalized = await acmeClient.FinalizeAsync(new Uri(order.Finalize!), csrDer);
            logger.LogInformation("已提交 CSR: status={Status}", finalized.Status);

            Console.WriteLine("\n[6/6] 等待证书签发并下载...");
            order = await PollOrderAsync(acmeClient, acmeClient.LastOrderUrl!, "valid", TimeSpan.FromMinutes(3), logger);
            if (order.Status != "valid")
            {
                Console.WriteLine($"签发失败: {order.Error?.Detail}");
                return 3;
            }

            using var pem = await acmeClient.DownloadCertificateAsync(new Uri(order.Certificate!), certKey);
            var baseName = domain.Replace('*', '_');
            var certPath = Path.Combine(AppContext.BaseDirectory, $"{baseName}.fullchain.pem");
            var keyPath = Path.Combine(AppContext.BaseDirectory, $"{baseName}.key.pem");
            var pfxPath = Path.Combine(AppContext.BaseDirectory, $"{baseName}.pfx");
            await File.WriteAllTextAsync(certPath, pem.FullChainPem);
            await File.WriteAllTextAsync(keyPath, pem.PrivateKeyPem);
            await File.WriteAllBytesAsync(pfxPath, pem.ExportPfx());
            Console.WriteLine($"\n证书已保存: {certPath}");
            Console.WriteLine($"私钥已保存: {keyPath}");
            Console.WriteLine($"PFX 已保存: {pfxPath}");
            return 0;
        }
        finally
        {
            httpServer?.Stop();
            if (provider is not null)
            {
                await CleanupRecordsAsync(provider, credentials!, createdRecords, logger);
            }
        }
    }

    private static async Task SolveChallengeAsync(
        AcmeClient client,
        AcmeKey accountKey,
        string challengeType,
        IDnsProvider? provider,
        IReadOnlyDictionary<string, object?>? credentials,
        ConcurrentDictionary<string, string> tokens,
        Uri authzUrl,
        List<(string Domain, string RecordName, string Value)> createdRecords,
        ILogger logger)
    {
        var authz = await client.GetAuthorizationAsync(authzUrl);
        var identifier = authz.Identifier?.Value ?? throw new InvalidOperationException("授权缺少 identifier");
        logger.LogInformation("处理授权: {Domain} (wildcard={Wildcard})", identifier, authz.Wildcard);

        var challenge = authz.Challenges?.FirstOrDefault(c => c.Type == challengeType)
            ?? throw new InvalidOperationException($"缺少 {challengeType} 挑战");
        var keyAuthz = ChallengeHelper.ComputeKeyAuthorization(challenge.Token!, accountKey);

        if (challengeType == "dns-01")
        {
            await SolveDns01Async(client, provider!, credentials!, identifier, challenge, keyAuthz, createdRecords, logger);
        }
        else
        {
            await SolveHttp01Async(client, tokens, identifier, challenge, keyAuthz, logger);
        }
    }

    private static async Task SolveDns01Async(
        AcmeClient client,
        IDnsProvider provider,
        IReadOnlyDictionary<string, object?> credentials,
        string identifier,
        AcmeChallenge challenge,
        string keyAuthz,
        List<(string Domain, string RecordName, string Value)> createdRecords,
        ILogger logger)
    {
        var txtValue = ChallengeHelper.ComputeDnsTxtRecordValue(keyAuthz);

        // 通配符授权 identifier 为 *.example.com，TXT 记录名必须去掉 *.（同 acme.sh 的 dns-01 处理）。
        var normalizedIdentifier = identifier.StartsWith("*.", StringComparison.Ordinal)
            ? identifier[2..]
            : identifier;
        var recordName = $"_acme-challenge.{normalizedIdentifier}";

        Console.WriteLine($"  创建 TXT 记录 {recordName} = {txtValue}");
        var create = await provider.CreateTxtRecordAsync(normalizedIdentifier, recordName, txtValue, credentials);
        if (!create.Success)
        {
            throw new InvalidOperationException($"创建 TXT 记录失败: {create.Message} {create.Details}");
        }

        createdRecords.Add((normalizedIdentifier, recordName, txtValue));

        Console.Write("  等待 DNS 生效");
        using var http = new HttpClient();
        var propagated = await WaitForTxtPropagationAsync(http, recordName, txtValue, logger);
        Console.WriteLine();

        if (!propagated)
        {
            throw new InvalidOperationException("等待 DNS 传播超时（3 分钟），请检查记录是否已在公网生效");
        }

        await TriggerAndPollValidationAsync(client, challenge, logger);
    }

    private static async Task SolveHttp01Async(
        AcmeClient client,
        ConcurrentDictionary<string, string> tokens,
        string identifier,
        AcmeChallenge challenge,
        string keyAuthz,
        ILogger logger)
    {
        Console.WriteLine($"  暴露 http://{identifier}/.well-known/acme-challenge/{challenge.Token}");
        tokens[challenge.Token!] = keyAuthz;
        try
        {
            await TriggerAndPollValidationAsync(client, challenge, logger);
        }
        finally
        {
            tokens.TryRemove(challenge.Token!, out _);
        }
    }

    private static async Task TriggerAndPollValidationAsync(AcmeClient client, AcmeChallenge challenge, ILogger logger)
    {
        var validated = await client.ValidateChallengeAsync(new Uri(challenge.Url!));
        logger.LogInformation("  验证触发: status={Status}", validated.Status);

        for (int i = 0; i < 30; i++)
        {
            await Task.Delay(TimeSpan.FromSeconds(3));
            var current = await client.GetChallengeAsync(new Uri(challenge.Url!));
            if (current.Status is "valid" or "invalid")
            {
                if (current.Status != "valid")
                {
                    throw new InvalidOperationException($"挑战验证失败: {current.Error?.Detail}");
                }

                logger.LogInformation("  挑战通过: status={Status}", current.Status);
                return;
            }
        }

        throw new TimeoutException("等待挑战验证超时");
    }

    private static async Task<AcmeOrder> PollOrderAsync(
        AcmeClient client,
        string orderUrl,
        string targetStatus,
        TimeSpan timeout,
        ILogger logger)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            var order = await client.GetOrderAsync(new Uri(orderUrl));
            logger.LogInformation("  订单状态: {Status}", order.Status);
            if (order.Status == targetStatus || order.Status is "valid" or "invalid")
            {
                return order;
            }

            await Task.Delay(TimeSpan.FromSeconds(5));
        }

        throw new TimeoutException($"等待订单 {targetStatus} 超时");
    }

    private static async Task<bool> WaitForTxtPropagationAsync(HttpClient http, string recordName, string expectedValue, ILogger logger)
    {
        var deadline = DateTime.UtcNow.AddMinutes(3);
        while (DateTime.UtcNow < deadline)
        {
            var values = await QueryTxtFromPublicResolversAsync(http, recordName, logger);
            if (values.Contains(expectedValue))
            {
                return true;
            }

            Console.Write('.');
            await Task.Delay(TimeSpan.FromSeconds(5));
        }

        return false;
    }

    private static async Task<HashSet<string>> QueryTxtFromPublicResolversAsync(HttpClient http, string name, ILogger logger)
    {
        var result = new HashSet<string>();
        var endpoints = new[]
        {
            $"https://dns.google/resolve?name={Uri.EscapeDataString(name)}&type=TXT",
            $"https://cloudflare-dns.com/dns-query?name={Uri.EscapeDataString(name)}&type=TXT",
            $"https://223.5.5.5/resolve?name={Uri.EscapeDataString(name)}&type=TXT",
        };

        foreach (var url in endpoints)
        {
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, url);
                request.Headers.TryAddWithoutValidation("accept", "application/dns-json");
                var response = await http.SendAsync(request);
                if (!response.IsSuccessStatusCode)
                {
                    continue;
                }

                var json = await response.Content.ReadAsStringAsync();
                using var doc = JsonDocument.Parse(json);
                if (!doc.RootElement.TryGetProperty("Answer", out var answers))
                {
                    continue;
                }

                foreach (var answer in answers.EnumerateArray())
                {
                    if (answer.TryGetProperty("data", out var data))
                    {
                        result.Add((data.GetString() ?? string.Empty).Trim().Trim('"'));
                    }
                }
            }
            catch (Exception ex)
            {
                logger.LogDebug("查询解析器失败 {Url}: {Message}", url, ex.Message);
            }
        }

        return result;
    }

    private static async Task CleanupRecordsAsync(
        IDnsProvider provider,
        IReadOnlyDictionary<string, object?> credentials,
        List<(string Domain, string RecordName, string Value)> records,
        ILogger logger)
    {
        foreach (var (domain, recordName, _) in records)
        {
            try
            {
                var result = await provider.DeleteAllTxtRecordsByNameAsync(domain, recordName, credentials);
                logger.LogInformation("清理 TXT 记录 {RecordName}: {Message}", recordName, result.Message);
            }
            catch (Exception ex)
            {
                logger.LogWarning("清理 TXT 记录 {RecordName} 失败: {Message}", recordName, ex.Message);
            }
        }
    }

    private static async Task SelfCheckAsync(int port, ConcurrentDictionary<string, string> tokens)
    {
        const string checkToken = "__self_check__";
        tokens[checkToken] = "ok";
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
            var body = await http.GetStringAsync($"http://127.0.0.1:{port}/.well-known/acme-challenge/{checkToken}");
            if (body != "ok")
            {
                throw new InvalidOperationException($"自检响应异常: {body}");
            }

            Console.WriteLine($"HTTP 服务自检通过 (127.0.0.1:{port})");
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException(
                $"HTTP 服务自检失败（端口 {port} 无法访问）。Windows 上绑定 80 端口需要管理员权限，或改用更高端口并在路由器/防火墙做端口转发。详细信息: {ex.Message}");
        }
        finally
        {
            tokens.TryRemove(checkToken, out _);
        }
    }

    private static AcmeKey LoadOrCreateAccountKey(ILogger logger)
    {
        var path = Path.Combine(AppContext.BaseDirectory, "acmeforge-account-key.pem");
        if (File.Exists(path))
        {
            var key = AcmeKey.FromPem(File.ReadAllText(path));
            logger.LogInformation("复用账户密钥: {Path}", path);
            return key;
        }

        var newKey = AcmeKey.Generate(AcmeKeyAlgorithm.ES256);
        File.WriteAllText(path, newKey.ToPem());
        logger.LogInformation("已生成新账户密钥并保存: {Path}", path);
        return newKey;
    }

    private static ServiceProvider BuildServices()
    {
        var configuration = new ConfigurationBuilder()
            .AddEnvironmentVariables()
            .Build();

        var services = new ServiceCollection();
        services.AddLogging(builder => builder.AddConsole());
        services.AddHttpClient();
        services.AddHttpClient("acme");
        services.AddHttpClient("Cloudflare");
        services.AddHttpClient("DnsPod");
        services.AddSingleton<IConfiguration>(configuration);
        services.AddSingleton<IDnsProvider, CloudflareDnsProvider>();
        services.AddSingleton<IDnsProvider, DnsPodDnsProvider>();
        return services.BuildServiceProvider();
    }

    private static IReadOnlyDictionary<string, object?> ReadCredentials(string providerName)
    {
        var result = new Dictionary<string, object?>();
        if (providerName == "cloudflare")
        {
            result["api_token"] = ReadNonEmpty("Cloudflare API Token（Zone.DNS:Edit 权限）");
        }
        else
        {
            result["secretId"] = ReadNonEmpty("DNSPod SecretId");
            result["secretKey"] = ReadNonEmpty("DNSPod SecretKey");
        }

        return result;
    }

    private static string ReadChoice(string label, string[] options)
    {
        while (true)
        {
            Console.Write($"{label} ({string.Join("/", options)}): ");
            var input = Console.ReadLine()?.Trim().ToLowerInvariant();
            if (options.Contains(input))
            {
                return input!;
            }

            Console.WriteLine($"无效输入，请输入: {string.Join("/", options)}");
        }
    }

    private static string ReadNonEmpty(string label)
    {
        while (true)
        {
            Console.Write($"{label}: ");
            var input = Console.ReadLine()?.Trim();
            if (!string.IsNullOrWhiteSpace(input))
            {
                return input!;
            }

            Console.WriteLine("输入不能为空");
        }
    }

    private static int ReadInt(string label, int defaultValue)
    {
        while (true)
        {
            Console.Write($"{label} [默认 {defaultValue}]: ");
            var input = Console.ReadLine()?.Trim();
            if (string.IsNullOrWhiteSpace(input))
            {
                return defaultValue;
            }

            if (int.TryParse(input, out var value) && value is > 0 and <= 65535)
            {
                return value;
            }

            Console.WriteLine("请输入有效的端口号 (1-65535)");
        }
    }

    /// <summary>极简 HTTP/1.1 服务器，仅用于暴露 http-01 的 /.well-known/acme-challenge/{token}。AOT 安全。</summary>
    private sealed class SimpleHttpServer
    {
        private readonly TcpListener _listener;
        private readonly ConcurrentDictionary<string, string> _tokens;
        private readonly CancellationTokenSource _cts = new();

        public SimpleHttpServer(int port, ConcurrentDictionary<string, string> tokens)
        {
            _listener = new TcpListener(IPAddress.Any, port);
            _tokens = tokens;
        }

        public void Start() => _listener.Start();

        public void Stop()
        {
            try
            {
                _cts.Cancel();
                _listener.Stop();
            }
            catch
            {
                // 忽略停止异常
            }
        }

        public async Task RunAsync()
        {
            while (!_cts.IsCancellationRequested)
            {
                TcpClient? client = null;
                try
                {
                    client = await _listener.AcceptTcpClientAsync(_cts.Token);
                }
                catch
                {
                    break;
                }

                _ = Task.Run(() => HandleClient(client));
            }
        }

        private async Task HandleClient(TcpClient client)
        {
            using (client)
            {
                try
                {
                    using var stream = client.GetStream();
                    var reader = new StreamReader(stream, Encoding.ASCII, leaveOpen: true);
                    var requestLine = await reader.ReadLineAsync();
                    if (requestLine is null)
                    {
                        return;
                    }

                    var parts = requestLine.Split(' ');
                    var path = parts.Length > 1 ? parts[1] : "/";

                    while (!string.IsNullOrEmpty(await reader.ReadLineAsync()))
                    {
                        // 消费剩余请求头
                    }

                    if (parts.Length > 0 && parts[0] == "GET" &&
                        path.StartsWith("/.well-known/acme-challenge/", StringComparison.Ordinal))
                    {
                        var token = path.Substring("/.well-known/acme-challenge/".Length);
                        if (_tokens.TryGetValue(token, out var value))
                        {
                            await WriteResponseAsync(stream, 200, "text/plain", Encoding.UTF8.GetBytes(value));
                            return;
                        }
                    }

                    await WriteResponseAsync(stream, 404, "text/plain", Encoding.UTF8.GetBytes("Not Found"));
                }
                catch
                {
                    // 忽略单个连接错误
                }
            }
        }

        private static async Task WriteResponseAsync(Stream stream, int status, string contentType, byte[] body)
        {
            var reason = status == 200 ? "OK" : "Not Found";
            var header = Encoding.ASCII.GetBytes(
                $"HTTP/1.1 {status} {reason}\r\nContent-Type: {contentType}\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n");
            await stream.WriteAsync(header);
            await stream.WriteAsync(body);
        }
    }
}
