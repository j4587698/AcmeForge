using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace AcmeForge.Dns;

/// <summary>
/// GoDaddy DNS API 提供商。
/// </summary>
public class GoDaddyDnsProvider : IDnsProvider
{
    private readonly ILogger<GoDaddyDnsProvider> _logger;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IConfiguration _configuration;
    private readonly HttpClient _httpClient;

    public GoDaddyDnsProvider(
        ILogger<GoDaddyDnsProvider> logger,
        IHttpClientFactory httpClientFactory,
        IConfiguration configuration)
    {
        _logger = logger;
        _httpClientFactory = httpClientFactory;
        _configuration = configuration;
        _httpClient = _httpClientFactory.CreateClient("GoDaddy");
        _httpClient.BaseAddress = new Uri("https://api.godaddy.com/v1/");
    }

    public string Name => "godaddy";
    public string DisplayName => "GoDaddy";
    public bool RequiresCredentials => true;

    public async Task<DnsOperationResult> CreateTxtRecordAsync(
        string domain,
        string recordName,
        string recordValue,
        IReadOnlyDictionary<string, object?>? credentials)
    {
        try
        {
            var apiKey = GetApiKey(credentials);
            var apiSecret = GetApiSecret(credentials);
            if (string.IsNullOrEmpty(apiKey) || string.IsNullOrEmpty(apiSecret))
            {
                return new DnsOperationResult { Success = false, Message = "GoDaddy API Key 或 Secret 未提供", ErrorCode = "MISSING_CREDENTIALS" };
            }

            var rootDomain = DnsDomainHelper.ExtractRootDomain(domain);
            var relativeName = GetRelativeRecordName(recordName, rootDomain);
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("sso-key", $"{apiKey}:{apiSecret}");

            var existingRecords = (await GetExistingTxtRecords(rootDomain, relativeName, apiKey, apiSecret)).ToList();
            existingRecords.Add(new GoDaddyDnsRecord
            {
                Name = relativeName,
                Type = "TXT",
                Data = recordValue,
                Ttl = 600,
            });

            var json = JsonSerializer.Serialize(existingRecords, DnsJsonContext.Instance.ListGoDaddyDnsRecord);
            var content = new StringContent(json, Encoding.UTF8, "application/json");
            var response = await _httpClient.PatchAsync($"domains/{rootDomain}/records", content);
            var responseContent = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("创建 GoDaddy DNS 记录失败: {StatusCode} - {Content}", response.StatusCode, responseContent);
                return new DnsOperationResult { Success = false, Message = $"创建 DNS 记录失败: {response.StatusCode}", ErrorCode = "CREATE_FAILED", Details = responseContent };
            }

            return new DnsOperationResult { Success = true, Message = "DNS 记录创建成功", Details = $"Domain: {rootDomain}, Record: {relativeName}" };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "创建 GoDaddy DNS 记录异常: {RecordName}", recordName);
            return new DnsOperationResult { Success = false, Message = $"创建 DNS 记录异常: {ex.Message}", ErrorCode = "EXCEPTION", Details = ex.ToString() };
        }
    }

    public async Task<DnsOperationResult> DeleteTxtRecordAsync(
        string domain,
        string recordName,
        string recordValue,
        IReadOnlyDictionary<string, object?>? credentials)
    {
        try
        {
            var apiKey = GetApiKey(credentials);
            var apiSecret = GetApiSecret(credentials);
            if (string.IsNullOrEmpty(apiKey) || string.IsNullOrEmpty(apiSecret))
            {
                return new DnsOperationResult { Success = false, Message = "GoDaddy API Key 或 Secret 未提供", ErrorCode = "MISSING_CREDENTIALS" };
            }

            var rootDomain = DnsDomainHelper.ExtractRootDomain(domain);
            var relativeName = GetRelativeRecordName(recordName, rootDomain);
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("sso-key", $"{apiKey}:{apiSecret}");

            var existingRecords = (await GetExistingTxtRecords(rootDomain, relativeName, apiKey, apiSecret)).ToList();
            if (existingRecords.All(r => r.Data != recordValue))
            {
                return new DnsOperationResult { Success = true, Message = "记录不存在，无需删除" };
            }

            var remainingRecords = existingRecords.Where(r => r.Data != recordValue).ToList();

            var response = await _httpClient.DeleteAsync($"domains/{rootDomain}/records/TXT/{relativeName}");
            var responseContent = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode && response.StatusCode != HttpStatusCode.NotFound)
            {
                _logger.LogError("删除 GoDaddy DNS 记录失败: {StatusCode} - {Content}", response.StatusCode, responseContent);
                return new DnsOperationResult { Success = false, Message = $"删除 DNS 记录失败: {response.StatusCode}", ErrorCode = "DELETE_FAILED", Details = responseContent };
            }

            if (remainingRecords.Count > 0)
            {
                var json = JsonSerializer.Serialize(remainingRecords, DnsJsonContext.Instance.ListGoDaddyDnsRecord);
                var content = new StringContent(json, Encoding.UTF8, "application/json");
                await _httpClient.PatchAsync($"domains/{rootDomain}/records", content);
            }

            return new DnsOperationResult { Success = true, Message = "DNS 记录删除成功" };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "删除 GoDaddy DNS 记录异常: {RecordName}", recordName);
            return new DnsOperationResult { Success = false, Message = $"删除 DNS 记录异常: {ex.Message}", ErrorCode = "EXCEPTION", Details = ex.ToString() };
        }
    }

    public async Task<DnsTestResult> TestConnectionAsync(IReadOnlyDictionary<string, object?>? credentials)
    {
        try
        {
            var apiKey = GetApiKey(credentials);
            var apiSecret = GetApiSecret(credentials);
            if (string.IsNullOrEmpty(apiKey) || string.IsNullOrEmpty(apiSecret))
            {
                return new DnsTestResult { Success = false, Message = "GoDaddy API Key 或 Secret 未提供", ErrorCode = "MISSING_CREDENTIALS" };
            }

            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("sso-key", $"{apiKey}:{apiSecret}");

            var response = await _httpClient.GetAsync("domains");
            var responseContent = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("GoDaddy API 认证失败: {StatusCode} - {Content}", response.StatusCode, responseContent);
                return new DnsTestResult { Success = false, Message = $"API 认证失败: {response.StatusCode}", ErrorCode = "AUTH_FAILED", Details = responseContent };
            }

            var domains = JsonSerializer.Deserialize(responseContent, DnsJsonContext.Instance.ListGoDaddyDomain);
            var domainCount = domains?.Count ?? 0;
            return new DnsTestResult { Success = true, Message = "GoDaddy API 连接测试成功", Details = $"找到 {domainCount} 个域名" };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "测试 GoDaddy DNS 连接异常");
            return new DnsTestResult { Success = false, Message = $"连接测试异常: {ex.Message}", ErrorCode = "EXCEPTION", Details = ex.ToString() };
        }
    }

    public async Task<DnsOperationResult> DeleteAllTxtRecordsByNameAsync(
        string domain,
        string recordName,
        IReadOnlyDictionary<string, object?>? credentials)
    {
        try
        {
            var apiKey = GetApiKey(credentials);
            var apiSecret = GetApiSecret(credentials);
            if (string.IsNullOrEmpty(apiKey) || string.IsNullOrEmpty(apiSecret))
            {
                return new DnsOperationResult { Success = false, Message = "缺少 GoDaddy API 凭据", ErrorCode = "MISSING_CREDENTIALS" };
            }

            var rootDomain = DnsDomainHelper.ExtractRootDomain(domain);
            var relativeName = GetRelativeRecordName(recordName, rootDomain);
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("sso-key", $"{apiKey}:{apiSecret}");

            var response = await _httpClient.DeleteAsync($"domains/{rootDomain}/records/TXT/{relativeName}");
            var responseContent = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode && response.StatusCode != HttpStatusCode.NotFound)
            {
                _logger.LogError("GoDaddy 删除 DNS 记录失败: {StatusCode} - {Content}", response.StatusCode, responseContent);
                return new DnsOperationResult { Success = false, Message = $"删除 DNS 记录失败: {response.StatusCode}", ErrorCode = "DELETE_FAILED", Details = responseContent };
            }

            return new DnsOperationResult { Success = true, Message = "DNS TXT 记录已删除", Details = $"已删除 {relativeName} 的所有 TXT 记录" };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "GoDaddy 删除所有 DNS TXT 记录时发生错误: {RecordName}", recordName);
            return new DnsOperationResult { Success = false, Message = $"删除 DNS TXT 记录时发生错误: {ex.Message}", ErrorCode = "EXCEPTION" };
        }
    }

    private string? GetApiKey(IReadOnlyDictionary<string, object?>? credentials)
        => credentials?.GetValueOrDefault("apiKey")?.ToString()
           ?? credentials?.GetValueOrDefault("api_key")?.ToString()
           ?? _configuration["DnsProviders:GoDaddy:ApiKey"];

    private string? GetApiSecret(IReadOnlyDictionary<string, object?>? credentials)
        => credentials?.GetValueOrDefault("apiSecret")?.ToString()
           ?? credentials?.GetValueOrDefault("api_secret")?.ToString()
           ?? _configuration["DnsProviders:GoDaddy:ApiSecret"];

    private async Task<IEnumerable<GoDaddyDnsRecord>> GetExistingTxtRecords(string domain, string recordName, string apiKey, string apiSecret)
    {
        try
        {
            var response = await _httpClient.GetAsync($"domains/{domain}/records/TXT/{recordName}");
            var responseContent = await response.Content.ReadAsStringAsync();

            if (response.StatusCode == HttpStatusCode.NotFound)
            {
                return Enumerable.Empty<GoDaddyDnsRecord>();
            }

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("获取 GoDaddy DNS 记录失败: {StatusCode} - {Content}", response.StatusCode, responseContent);
                return Enumerable.Empty<GoDaddyDnsRecord>();
            }

            var records = JsonSerializer.Deserialize(responseContent, DnsJsonContext.Instance.ListGoDaddyDnsRecord);
            return records ?? Enumerable.Empty<GoDaddyDnsRecord>();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "获取 GoDaddy DNS 记录异常");
            return Enumerable.Empty<GoDaddyDnsRecord>();
        }
    }

    private static string GetRelativeRecordName(string recordName, string rootDomain)
    {
        if (recordName.EndsWith($".{rootDomain}", StringComparison.OrdinalIgnoreCase))
        {
            return recordName[..^(rootDomain.Length + 1)];
        }

        if (recordName.Equals(rootDomain, StringComparison.OrdinalIgnoreCase))
        {
            return "@";
        }

        return recordName;
    }
}

public sealed class GoDaddyDomain
{
    [System.Text.Json.Serialization.JsonPropertyName("domain")]
    public string DomainName { get; set; } = string.Empty;

    [System.Text.Json.Serialization.JsonPropertyName("status")]
    public string Status { get; set; } = string.Empty;
}

public sealed class GoDaddyDnsRecord
{
    [System.Text.Json.Serialization.JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [System.Text.Json.Serialization.JsonPropertyName("type")]
    public string Type { get; set; } = string.Empty;

    [System.Text.Json.Serialization.JsonPropertyName("data")]
    public string Data { get; set; } = string.Empty;

    [System.Text.Json.Serialization.JsonPropertyName("ttl")]
    public int Ttl { get; set; } = 600;
}