using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace AcmeForge.Dns;

/// <summary>
/// DNSPod 传统 API (dnsapi.cn) 提供商。
/// </summary>
public class DnsPodTraditionalDnsProvider : IDnsProvider
{
    private readonly ILogger<DnsPodTraditionalDnsProvider> _logger;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IConfiguration _configuration;
    private readonly HttpClient _httpClient;

    public DnsPodTraditionalDnsProvider(
        ILogger<DnsPodTraditionalDnsProvider> logger,
        IHttpClientFactory httpClientFactory,
        IConfiguration configuration)
    {
        _logger = logger;
        _httpClientFactory = httpClientFactory;
        _configuration = configuration;
        _httpClient = _httpClientFactory.CreateClient("DnsPodTraditional");
        _httpClient.BaseAddress = new Uri("https://dnsapi.cn/");
    }

    public string Name => "dnspod-traditional";
    public string DisplayName => "DNSPod (传统API)";
    public bool RequiresCredentials => true;

    public async Task<DnsOperationResult> CreateTxtRecordAsync(
        string domain,
        string recordName,
        string recordValue,
        IReadOnlyDictionary<string, object?>? credentials)
    {
        try
        {
            var loginToken = GetLoginToken(credentials);
            var secretId = GetSecretId(credentials);
            var secretKey = GetSecretKey(credentials);

            if (string.IsNullOrEmpty(loginToken) && (string.IsNullOrEmpty(secretId) || string.IsNullOrEmpty(secretKey)))
            {
                return new DnsOperationResult { Success = false, Message = "DNSPod 登录令牌或 Secret 未提供", ErrorCode = "MISSING_CREDENTIALS" };
            }

            var domainName = DnsDomainHelper.ExtractRootDomain(domain);
            var domainId = await GetDomainId(domainName, loginToken, secretId, secretKey);
            if (string.IsNullOrEmpty(domainId))
            {
                return new DnsOperationResult { Success = false, Message = $"无法获取域名 {domainName} 的 ID", ErrorCode = "DOMAIN_NOT_FOUND" };
            }

            var subDomain = DnsDomainHelper.ExtractSubDomain(recordName, domainName);

            var existingRecordId = await GetRecordId(domainId, subDomain, recordValue, loginToken, secretId, secretKey);
            if (!string.IsNullOrEmpty(existingRecordId))
            {
                return new DnsOperationResult { Success = true, Message = $"DNS TXT 记录已存在: {recordName} = {recordValue}", RecordId = existingRecordId };
            }

            var recordId = await CreateRecord(domainId, subDomain, recordValue, loginToken, secretId, secretKey);
            if (!string.IsNullOrEmpty(recordId))
            {
                return new DnsOperationResult { Success = true, Message = $"DNS TXT 记录创建成功: {recordName} = {recordValue}", RecordId = recordId };
            }

            return new DnsOperationResult { Success = false, Message = "创建 DNS TXT 记录失败", ErrorCode = "CREATE_FAILED" };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "创建 DNS TXT 记录时发生错误: {RecordName}", recordName);
            return new DnsOperationResult { Success = false, Message = $"创建 DNS TXT 记录时发生错误: {ex.Message}", ErrorCode = "EXCEPTION" };
        }
    }

    public async Task<DnsTestResult> TestConnectionAsync(IReadOnlyDictionary<string, object?>? credentials)
    {
        try
        {
            var loginToken = GetLoginToken(credentials);
            var secretId = GetSecretId(credentials);
            var secretKey = GetSecretKey(credentials);

            if (string.IsNullOrEmpty(loginToken) && (string.IsNullOrEmpty(secretId) || string.IsNullOrEmpty(secretKey)))
            {
                return new DnsTestResult { Success = false, Message = "DNSPod 登录令牌或 Secret 未提供", ErrorCode = "MISSING_CREDENTIALS" };
            }

            var parameters = new Dictionary<string, string>();
            parameters["login_token"] = !string.IsNullOrEmpty(loginToken) ? loginToken! : $"{secretId},{secretKey}";

            var response = await SendRequest("Domain.List", parameters);
            var responseContent = await response.Content.ReadAsStringAsync();

            var listResult = JsonSerializer.Deserialize(responseContent, DnsJsonContext.Instance.DnsPodTraditionalListDomainsResponse);

            if (response.IsSuccessStatusCode && IsSuccessful(listResult?.Status))
            {
                return new DnsTestResult { Success = true, Message = "DNSPod 传统 API 连接测试成功" };
            }

            return new DnsTestResult { Success = false, Message = "DNSPod 传统 API 连接测试失败", ErrorCode = "CONNECTION_FAILED", Details = responseContent };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "测试 DNSPod 传统 API 连接时发生错误");
            return new DnsTestResult { Success = false, Message = $"测试连接时发生错误: {ex.Message}", ErrorCode = "EXCEPTION" };
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
            var loginToken = GetLoginToken(credentials);
            var secretId = GetSecretId(credentials);
            var secretKey = GetSecretKey(credentials);

            var domainName = DnsDomainHelper.ExtractRootDomain(domain);
            var domainId = await GetDomainId(domainName, loginToken, secretId, secretKey);
            if (string.IsNullOrEmpty(domainId))
            {
                return new DnsOperationResult { Success = false, Message = $"无法获取域名 {domainName} 的 ID", ErrorCode = "DOMAIN_NOT_FOUND" };
            }

            var subDomain = DnsDomainHelper.ExtractSubDomain(recordName, domainName);
            var recordId = await GetRecordId(domainId, subDomain, recordValue, loginToken, secretId, secretKey);
            if (string.IsNullOrEmpty(recordId))
            {
                return new DnsOperationResult { Success = false, Message = "找不到要删除的 DNS TXT 记录", ErrorCode = "RECORD_NOT_FOUND" };
            }

            var success = await DeleteRecord(domainId, recordId, loginToken, secretId, secretKey);
            if (success)
            {
                return new DnsOperationResult { Success = true, Message = $"DNS TXT 记录删除成功: {recordName}", RecordId = recordId };
            }

            return new DnsOperationResult { Success = false, Message = "删除 DNS TXT 记录失败", ErrorCode = "DELETE_FAILED" };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "删除 DNS TXT 记录时发生错误: {RecordName}", recordName);
            return new DnsOperationResult { Success = false, Message = $"删除 DNS TXT 记录时发生错误: {ex.Message}", ErrorCode = "EXCEPTION" };
        }
    }

    public async Task<DnsOperationResult> DeleteAllTxtRecordsByNameAsync(
        string domain,
        string recordName,
        IReadOnlyDictionary<string, object?>? credentials)
    {
        try
        {
            var loginToken = GetLoginToken(credentials);
            var secretId = GetSecretId(credentials);
            var secretKey = GetSecretKey(credentials);

            var domainName = DnsDomainHelper.ExtractRootDomain(domain);
            var domainId = await GetDomainId(domainName, loginToken, secretId, secretKey);
            if (string.IsNullOrEmpty(domainId))
            {
                return new DnsOperationResult { Success = false, Message = $"无法获取域名 {domainName} 的 ID", ErrorCode = "DOMAIN_NOT_FOUND" };
            }

            var subDomain = DnsDomainHelper.ExtractSubDomain(recordName, domainName);
            var parameters = new Dictionary<string, string>
            {
                ["domain_id"] = domainId,
                ["sub_domain"] = subDomain,
                ["record_type"] = "TXT",
            };
            parameters["login_token"] = !string.IsNullOrEmpty(loginToken) ? loginToken! : $"{secretId},{secretKey}";

            var response = await SendRequest("Record.List", parameters);
            var responseContent = await response.Content.ReadAsStringAsync();

            if (response.IsSuccessStatusCode)
            {
                var result = JsonSerializer.Deserialize(responseContent, DnsJsonContext.Instance.DnsPodTraditionalListRecordsResponse);
                if (result?.Records is { Count: > 0 })
                {
                    var deletedCount = 0;
                    foreach (var record in result.Records)
                    {
                        if (!string.IsNullOrEmpty(record.Id) && await DeleteRecord(domainId, record.Id, loginToken, secretId, secretKey))
                        {
                            deletedCount++;
                        }
                    }

                    return new DnsOperationResult { Success = true, Message = $"成功删除 {deletedCount} 条 DNS TXT 记录", Details = $"已删除 {deletedCount} 条记录" };
                }
            }

            return new DnsOperationResult { Success = true, Message = "没有找到匹配的记录或已全部删除" };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "删除所有 DNS TXT 记录时发生错误: {RecordName}", recordName);
            return new DnsOperationResult { Success = false, Message = $"删除 DNS TXT 记录时发生错误: {ex.Message}", ErrorCode = "EXCEPTION" };
        }
    }

    private string? GetLoginToken(IReadOnlyDictionary<string, object?>? credentials)
        => credentials?.GetValueOrDefault("loginToken")?.ToString()
           ?? credentials?.GetValueOrDefault("login_token")?.ToString()
           ?? _configuration["DnsProviders:DnsPod:LoginToken"];

    private string? GetSecretId(IReadOnlyDictionary<string, object?>? credentials)
        => credentials?.GetValueOrDefault("secretId")?.ToString()
           ?? credentials?.GetValueOrDefault("SecretId")?.ToString()
           ?? credentials?.GetValueOrDefault("secret_id")?.ToString()
           ?? _configuration["DnsProviders:DnsPod:SecretId"];

    private string? GetSecretKey(IReadOnlyDictionary<string, object?>? credentials)
        => credentials?.GetValueOrDefault("secretKey")?.ToString()
           ?? credentials?.GetValueOrDefault("SecretKey")?.ToString()
           ?? credentials?.GetValueOrDefault("secret_key")?.ToString()
           ?? _configuration["DnsProviders:DnsPod:SecretKey"];

    private async Task<string?> GetDomainId(string domain, string? loginToken, string? secretId, string? secretKey)
    {
        try
        {
            var parameters = BuildAuthParameters(loginToken, secretId, secretKey);
            var response = await SendRequest("Domain.List", parameters);
            var responseContent = await response.Content.ReadAsStringAsync();

            if (response.IsSuccessStatusCode)
            {
                var result = JsonSerializer.Deserialize(responseContent, DnsJsonContext.Instance.DnsPodTraditionalListDomainsResponse);
                var targetDomain = result?.Domains?.FirstOrDefault(d =>
                    d.Name?.Equals(domain, StringComparison.OrdinalIgnoreCase) == true);
                return targetDomain?.Id;
            }

            _logger.LogWarning("未找到域名: {Domain}", domain);
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "获取域名 ID 时发生错误: {Domain}", domain);
            return null;
        }
    }

    private async Task<string?> CreateRecord(string domainId, string subDomain, string recordValue, string? loginToken, string? secretId, string? secretKey)
    {
        try
        {
            var parameters = new Dictionary<string, string>
            {
                ["domain_id"] = domainId,
                ["sub_domain"] = subDomain,
                ["record_type"] = "TXT",
                ["record_line"] = "默认",
                ["value"] = recordValue,
                ["ttl"] = "600",
            };
            AddAuthParameters(parameters, loginToken, secretId, secretKey);

            var response = await SendRequest("Record.Create", parameters);
            var responseContent = await response.Content.ReadAsStringAsync();

            if (response.IsSuccessStatusCode)
            {
                var result = JsonSerializer.Deserialize(responseContent, DnsJsonContext.Instance.DnsPodTraditionalCreateRecordResponse);
                return result?.Record?.Id;
            }

            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "创建记录时发生错误");
            return null;
        }
    }

    private async Task<string?> GetRecordId(string domainId, string subDomain, string recordValue, string? loginToken, string? secretId, string? secretKey)
    {
        try
        {
            var parameters = new Dictionary<string, string>
            {
                ["domain_id"] = domainId,
                ["sub_domain"] = subDomain,
                ["record_type"] = "TXT",
            };
            AddAuthParameters(parameters, loginToken, secretId, secretKey);

            var response = await SendRequest("Record.List", parameters);
            var responseContent = await response.Content.ReadAsStringAsync();

            if (response.IsSuccessStatusCode)
            {
                var result = JsonSerializer.Deserialize(responseContent, DnsJsonContext.Instance.DnsPodTraditionalListRecordsResponse);
                return result?.Records?.FirstOrDefault(r =>
                    r.Value?.Equals(recordValue, StringComparison.OrdinalIgnoreCase) == true)?.Id;
            }

            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "获取记录 ID 时发生错误");
            return null;
        }
    }

    private async Task<bool> DeleteRecord(string domainId, string recordId, string? loginToken, string? secretId, string? secretKey)
    {
        try
        {
            var parameters = new Dictionary<string, string>
            {
                ["domain_id"] = domainId,
                ["record_id"] = recordId,
            };
            AddAuthParameters(parameters, loginToken, secretId, secretKey);

            var response = await SendRequest("Record.Remove", parameters);
            var responseContent = await response.Content.ReadAsStringAsync();

            if (response.IsSuccessStatusCode)
            {
                var result = JsonSerializer.Deserialize(responseContent, DnsJsonContext.Instance.DnsPodTraditionalDeleteResponse);
                return IsSuccessful(result?.Status);
            }

            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "删除记录时发生错误");
            return false;
        }
    }

    private static Dictionary<string, string> BuildAuthParameters(string? loginToken, string? secretId, string? secretKey)
    {
        var parameters = new Dictionary<string, string>();
        AddAuthParameters(parameters, loginToken, secretId, secretKey);
        return parameters;
    }

    private static void AddAuthParameters(Dictionary<string, string> parameters, string? loginToken, string? secretId, string? secretKey)
    {
        parameters["login_token"] = !string.IsNullOrEmpty(loginToken) ? loginToken! : $"{secretId},{secretKey}";
    }

    private static bool IsSuccessful(DnsPodTraditionalStatus? status) => status?.Code == "1";

    private async Task<HttpResponseMessage> SendRequest(string action, Dictionary<string, string> parameters)
    {
        var content = new FormUrlEncodedContent(parameters);
        content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/x-www-form-urlencoded");

        var request = new HttpRequestMessage(HttpMethod.Post, action)
        {
            Content = content,
        };
        request.Headers.UserAgent.ParseAdd("AcmeForge/1.0");

        var response = await _httpClient.SendAsync(request);
        _logger.LogInformation("DNSPod 传统 API 请求: Action={Action}, Status={StatusCode}", action, response.StatusCode);
        return response;
    }
}

public sealed class DnsPodTraditionalStatus
{
    [JsonPropertyName("code")]
    public string? Code { get; set; }
    [JsonPropertyName("message")]
    public string? Message { get; set; }
}

public sealed class DnsPodTraditionalDomain
{
    [JsonPropertyName("id")]
    [JsonConverter(typeof(JsonStringOrNumberConverter))]
    public string? Id { get; set; }
    [JsonPropertyName("name")]
    public string? Name { get; set; }
}

public sealed class DnsPodTraditionalRecord
{
    [JsonPropertyName("id")]
    [JsonConverter(typeof(JsonStringOrNumberConverter))]
    public string? Id { get; set; }
    [JsonPropertyName("value")]
    public string? Value { get; set; }
}

public sealed class DnsPodTraditionalListDomainsResponse
{
    [JsonPropertyName("status")]
    public DnsPodTraditionalStatus? Status { get; set; }
    [JsonPropertyName("domains")]
    public List<DnsPodTraditionalDomain>? Domains { get; set; }
}

public sealed class DnsPodTraditionalListRecordsResponse
{
    [JsonPropertyName("status")]
    public DnsPodTraditionalStatus? Status { get; set; }
    [JsonPropertyName("records")]
    public List<DnsPodTraditionalRecord>? Records { get; set; }
}

public sealed class DnsPodTraditionalCreateRecordResponse
{
    [JsonPropertyName("status")]
    public DnsPodTraditionalStatus? Status { get; set; }
    [JsonPropertyName("record")]
    public DnsPodTraditionalRecord? Record { get; set; }
}

public sealed class DnsPodTraditionalDeleteResponse
{
    [JsonPropertyName("status")]
    public DnsPodTraditionalStatus? Status { get; set; }
}