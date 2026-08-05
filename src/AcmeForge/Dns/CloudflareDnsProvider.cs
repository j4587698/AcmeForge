using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace AcmeForge.Dns;

/// <summary>
/// Cloudflare DNS API 提供商。
/// </summary>
public class CloudflareDnsProvider : IDnsProvider
{
    private readonly ILogger<CloudflareDnsProvider> _logger;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IConfiguration _configuration;
    private readonly HttpClient _httpClient;

    public CloudflareDnsProvider(
        ILogger<CloudflareDnsProvider> logger,
        IHttpClientFactory httpClientFactory,
        IConfiguration configuration)
    {
        _logger = logger;
        _httpClientFactory = httpClientFactory;
        _configuration = configuration;
        _httpClient = _httpClientFactory.CreateClient("Cloudflare");
        _httpClient.BaseAddress = new Uri("https://api.cloudflare.com/client/v4/");
    }

    public string Name => "cloudflare";
    public string DisplayName => "Cloudflare";
    public bool RequiresCredentials => true;

    public async Task<DnsOperationResult> CreateTxtRecordAsync(
        string domain,
        string recordName,
        string recordValue,
        IReadOnlyDictionary<string, object?>? credentials)
    {
        try
        {
            var apiToken = GetApiToken(credentials);
            if (string.IsNullOrEmpty(apiToken))
            {
                return new DnsOperationResult { Success = false, Message = "Cloudflare API Token 未提供", ErrorCode = "MISSING_API_TOKEN" };
            }

            _httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", apiToken);

            var zoneId = await GetZoneId(domain);
            if (string.IsNullOrEmpty(zoneId))
            {
                return new DnsOperationResult { Success = false, Message = $"无法获取域名 {domain} 的 Zone ID", ErrorCode = "ZONE_NOT_FOUND" };
            }

            var existingRecord = await GetExistingTxtRecord(zoneId, recordName);
            if (existingRecord != null)
            {
                return await UpdateTxtRecord(zoneId, existingRecord.Id, recordName, recordValue);
            }

            var request = new CloudflareDnsRecordRequest
            {
                Type = "TXT",
                Name = recordName,
                Content = recordValue,
                Ttl = 120,
            };

            var json = JsonSerializer.Serialize(request, DnsJsonContext.Instance.CloudflareDnsRecordRequest);
            var content = new StringContent(json, Encoding.UTF8, "application/json");
            var response = await _httpClient.PostAsync($"zones/{zoneId}/dns_records", content);
            var responseContent = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("创建 Cloudflare DNS 记录失败: {StatusCode} - {Content}", response.StatusCode, responseContent);
                return new DnsOperationResult { Success = false, Message = $"创建 DNS 记录失败: {response.StatusCode}", ErrorCode = "CREATE_FAILED", Details = responseContent };
            }

            var result = JsonSerializer.Deserialize(responseContent, DnsJsonContext.Instance.CloudflareDnsResponse);
            if (result?.Success == true)
            {
                return new DnsOperationResult { Success = true, Message = "DNS 记录创建成功", RecordId = result.Result?.Id, Details = $"记录 ID: {result.Result?.Id}" };
            }

            return new DnsOperationResult { Success = false, Message = "创建 DNS 记录失败", ErrorCode = "API_ERROR", Details = responseContent };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "创建 Cloudflare DNS 记录异常: {RecordName}", recordName);
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
            var apiToken = GetApiToken(credentials);
            if (string.IsNullOrEmpty(apiToken))
            {
                return new DnsOperationResult { Success = false, Message = "Cloudflare API Token 未提供", ErrorCode = "MISSING_API_TOKEN" };
            }

            _httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", apiToken);

            var zoneId = await GetZoneId(domain);
            if (string.IsNullOrEmpty(zoneId))
            {
                return new DnsOperationResult { Success = false, Message = $"无法获取域名 {domain} 的 Zone ID", ErrorCode = "ZONE_NOT_FOUND" };
            }

            var existingRecord = await GetExistingTxtRecord(zoneId, recordName);
            if (existingRecord == null)
            {
                return new DnsOperationResult { Success = true, Message = "记录不存在，无需删除" };
            }

            var response = await _httpClient.DeleteAsync($"zones/{zoneId}/dns_records/{existingRecord.Id}");
            var responseContent = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("删除 Cloudflare DNS 记录失败: {StatusCode} - {Content}", response.StatusCode, responseContent);
                return new DnsOperationResult { Success = false, Message = $"删除 DNS 记录失败: {response.StatusCode}", ErrorCode = "DELETE_FAILED", Details = responseContent };
            }

            var result = JsonSerializer.Deserialize(responseContent, DnsJsonContext.Instance.CloudflareDnsResponse);
            if (result?.Success == true)
            {
                return new DnsOperationResult { Success = true, Message = "DNS 记录删除成功", RecordId = existingRecord.Id };
            }

            return new DnsOperationResult { Success = false, Message = "删除 DNS 记录失败", ErrorCode = "API_ERROR", Details = responseContent };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "删除 Cloudflare DNS 记录异常: {RecordName}", recordName);
            return new DnsOperationResult { Success = false, Message = $"删除 DNS 记录异常: {ex.Message}", ErrorCode = "EXCEPTION", Details = ex.ToString() };
        }
    }

    public async Task<DnsTestResult> TestConnectionAsync(IReadOnlyDictionary<string, object?>? credentials)
    {
        try
        {
            var apiToken = GetApiToken(credentials);
            if (string.IsNullOrEmpty(apiToken))
            {
                return new DnsTestResult { Success = false, Message = "Cloudflare API Token 未提供", ErrorCode = "MISSING_API_TOKEN" };
            }

            _httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", apiToken);

            var response = await _httpClient.GetAsync("user/tokens/verify");
            var responseContent = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("Cloudflare API 认证失败: {StatusCode} - {Content}", response.StatusCode, responseContent);
                return new DnsTestResult { Success = false, Message = $"API 认证失败: {response.StatusCode}", ErrorCode = "AUTH_FAILED", Details = responseContent };
            }

            var result = JsonSerializer.Deserialize(responseContent, DnsJsonContext.Instance.CloudflareTokenVerifyResponse);
            if (result?.Success == true)
            {
                return new DnsTestResult { Success = true, Message = "Cloudflare API 连接测试成功", Details = $"Token 状态: 有效, 权限: {string.Join(", ", result.Result?.Scope ?? Enumerable.Empty<string>())}" };
            }

            return new DnsTestResult { Success = false, Message = "API 连接测试失败", ErrorCode = "API_ERROR", Details = responseContent };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "测试 Cloudflare DNS 连接异常");
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
            var apiToken = credentials?["api_token"]?.ToString();
            if (string.IsNullOrEmpty(apiToken))
            {
                return new DnsOperationResult { Success = false, Message = "缺少 API Token", ErrorCode = "MISSING_TOKEN" };
            }

            var zoneId = await GetZoneId(domain);
            if (string.IsNullOrEmpty(zoneId))
            {
                return new DnsOperationResult { Success = false, Message = $"无法获取域名 {domain} 的 Zone ID", ErrorCode = "ZONE_NOT_FOUND" };
            }

            var records = await ListTxtRecords(zoneId, recordName, apiToken);
            if (records == null || records.Count == 0)
            {
                return new DnsOperationResult { Success = true, Message = "没有找到匹配的记录" };
            }

            var deletedCount = 0;
            foreach (var record in records)
            {
                if (await DeleteRecord(zoneId, record.Id, apiToken))
                {
                    deletedCount++;
                }
            }

            return new DnsOperationResult { Success = true, Message = $"成功删除 {deletedCount} 条 DNS TXT 记录", Details = $"已删除 {deletedCount} 条记录" };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Cloudflare 删除所有 DNS TXT 记录时发生错误: {RecordName}", recordName);
            return new DnsOperationResult { Success = false, Message = $"删除 DNS TXT 记录时发生错误: {ex.Message}", ErrorCode = "EXCEPTION" };
        }
    }

    private string? GetApiToken(IReadOnlyDictionary<string, object?>? credentials)
        => credentials?.GetValueOrDefault("api_token")?.ToString()
           ?? _configuration["DnsProviders:Cloudflare:ApiToken"];

    private async Task<string?> GetZoneId(string domain)
    {
        try
        {
            var rootDomain = DnsDomainHelper.ExtractRootDomain(domain);
            var response = await _httpClient.GetAsync($"zones?name={rootDomain}");
            var responseContent = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("获取 Zone ID 失败: {StatusCode} - {Content}", response.StatusCode, responseContent);
                return null;
            }

            var result = JsonSerializer.Deserialize(responseContent, DnsJsonContext.Instance.CloudflareZonesResponse);
            return result?.Result?.FirstOrDefault()?.Id;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "获取 Zone ID 异常: {Domain}", domain);
            return null;
        }
    }

    private async Task<CloudflareDnsRecord?> GetExistingTxtRecord(string zoneId, string recordName)
    {
        try
        {
            var response = await _httpClient.GetAsync($"zones/{zoneId}/dns_records?type=TXT&name={recordName}");
            var responseContent = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("查询现有 DNS 记录失败: {StatusCode} - {Content}", response.StatusCode, responseContent);
                return null;
            }

            var result = JsonSerializer.Deserialize(responseContent, DnsJsonContext.Instance.CloudflareDnsRecordsResponse);
            return result?.Result?.FirstOrDefault();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "查询现有 DNS 记录异常: {RecordName}", recordName);
            return null;
        }
    }

    private async Task<DnsOperationResult> UpdateTxtRecord(string zoneId, string recordId, string recordName, string recordValue)
    {
        try
        {
            var request = new CloudflareDnsRecordRequest { Type = "TXT", Name = recordName, Content = recordValue, Ttl = 120 };
            var json = JsonSerializer.Serialize(request, DnsJsonContext.Instance.CloudflareDnsRecordRequest);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            var response = await _httpClient.PutAsync($"zones/{zoneId}/dns_records/{recordId}", content);
            var responseContent = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("更新 Cloudflare DNS 记录失败: {StatusCode} - {Content}", response.StatusCode, responseContent);
                return new DnsOperationResult { Success = false, Message = $"更新 DNS 记录失败: {response.StatusCode}", ErrorCode = "UPDATE_FAILED", Details = responseContent };
            }

            var result = JsonSerializer.Deserialize(responseContent, DnsJsonContext.Instance.CloudflareDnsResponse);
            if (result?.Success == true)
            {
                return new DnsOperationResult { Success = true, Message = "DNS 记录更新成功", RecordId = recordId, Details = $"记录 ID: {recordId}" };
            }

            return new DnsOperationResult { Success = false, Message = "更新 DNS 记录失败", ErrorCode = "API_ERROR", Details = responseContent };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "更新 Cloudflare DNS 记录异常: {RecordName}", recordName);
            return new DnsOperationResult { Success = false, Message = $"更新 DNS 记录异常: {ex.Message}", ErrorCode = "EXCEPTION", Details = ex.ToString() };
        }
    }

    private async Task<List<CloudflareDnsRecord>> ListTxtRecords(string zoneId, string recordName, string apiToken)
    {
        try
        {
            var records = new List<CloudflareDnsRecord>();

            using var request = new HttpRequestMessage(HttpMethod.Get, $"zones/{zoneId}/dns_records?type=TXT&name={Uri.EscapeDataString(recordName)}");
            request.Headers.Add("Authorization", $"Bearer {apiToken}");

            var response = await _httpClient.SendAsync(request);
            var responseContent = await response.Content.ReadAsStringAsync();

            if (response.IsSuccessStatusCode)
            {
                var result = JsonSerializer.Deserialize(responseContent, DnsJsonContext.Instance.CloudflareDnsRecordsResponse);
                if (result?.Result != null)
                {
                    records = result.Result;
                }
            }

            return records;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "列出 TXT 记录时发生错误: {RecordName}", recordName);
            return new List<CloudflareDnsRecord>();
        }
    }

    private async Task<bool> DeleteRecord(string zoneId, string recordId, string apiToken)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Delete, $"zones/{zoneId}/dns_records/{recordId}");
            request.Headers.Add("Authorization", $"Bearer {apiToken}");
            var response = await _httpClient.SendAsync(request);
            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "删除 DNS 记录时发生错误: {RecordId}", recordId);
            return false;
        }
    }
}

/// <summary>Cloudflare 创建/更新 DNS 记录请求。</summary>
public sealed class CloudflareDnsRecordRequest
{
    [JsonPropertyName("type")]
    public string Type { get; set; } = "TXT";
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;
    [JsonPropertyName("content")]
    public string Content { get; set; } = string.Empty;
    [JsonPropertyName("ttl")]
    public int Ttl { get; set; }
}

public sealed class CloudflareDnsResponse
{
    [JsonPropertyName("success")]
    public bool Success { get; set; }
    [JsonPropertyName("result")]
    public CloudflareDnsRecord? Result { get; set; }
    [JsonPropertyName("errors")]
    public List<CloudflareErrorInfo>? Errors { get; set; }
    [JsonPropertyName("messages")]
    public List<CloudflareErrorInfo>? Messages { get; set; }
}

public sealed class CloudflareDnsRecordsResponse
{
    [JsonPropertyName("success")]
    public bool Success { get; set; }
    [JsonPropertyName("result")]
    public List<CloudflareDnsRecord>? Result { get; set; }
    [JsonPropertyName("errors")]
    public List<CloudflareErrorInfo>? Errors { get; set; }
}

public sealed class CloudflareZonesResponse
{
    [JsonPropertyName("success")]
    public bool Success { get; set; }
    [JsonPropertyName("result")]
    public List<CloudflareZone>? Result { get; set; }
    [JsonPropertyName("errors")]
    public List<CloudflareErrorInfo>? Errors { get; set; }
}

public sealed class CloudflareTokenVerifyResponse
{
    [JsonPropertyName("success")]
    public bool Success { get; set; }
    [JsonPropertyName("result")]
    public CloudflareTokenInfo? Result { get; set; }
    [JsonPropertyName("errors")]
    public List<CloudflareErrorInfo>? Errors { get; set; }
}

public sealed class CloudflareDnsRecord
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;
    [JsonPropertyName("type")]
    public string Type { get; set; } = string.Empty;
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;
    [JsonPropertyName("content")]
    public string Content { get; set; } = string.Empty;
    [JsonPropertyName("ttl")]
    public int Ttl { get; set; }
    [JsonPropertyName("proxied")]
    public bool Proxied { get; set; }
    [JsonPropertyName("created_on")]
    public DateTime CreatedOn { get; set; }
    [JsonPropertyName("modified_on")]
    public DateTime ModifiedOn { get; set; }
}

public sealed class CloudflareZone
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;
    [JsonPropertyName("status")]
    public string Status { get; set; } = string.Empty;
}

public sealed class CloudflareTokenInfo
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;
    [JsonPropertyName("status")]
    public string Status { get; set; } = string.Empty;
    [JsonPropertyName("expires_on")]
    public DateTime? ExpiresOn { get; set; }
    [JsonPropertyName("scope")]
    public List<string>? Scope { get; set; }
}

public sealed class CloudflareErrorInfo
{
    [JsonPropertyName("code")]
    public int Code { get; set; }
    [JsonPropertyName("message")]
    public string Message { get; set; } = string.Empty;
}